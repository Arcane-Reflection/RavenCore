import Foundation

/// A parsed CSV document (VAULT-05 engine half, 05-CONTEXT D-09/D-14).
///
/// `headers` is the first record; `rows` holds only the well-formed data
/// records; every malformed record lands in `malformedRows` with its record
/// index (0 = the header record) and a plain-language reason (T-05-06:
/// malformed rows never abort the parse — they are reported, the import
/// continues with the good rows).
///
/// `Equatable` is written by hand because tuple arrays (the pinned
/// `malformedRows` shape) cannot synthesize conformance.
public struct CSVDocument: Sendable, Equatable {
    /// The first record — the column names the mapper matches against.
    public var headers: [String]
    /// Well-formed data records (every field count == `headers.count`).
    public var rows: [[String]]
    /// Source record ordinal (0-based over content records) for each entry in
    /// `rows`, aligned 1:1. Malformed records in between do not shift these —
    /// a row keeps its true stream position, consistent with the
    /// `malformedRows` numbering. Empty lines never become records;
    /// whitespace-only lines do (and consume an ordinal, then are filtered).
    public var rowIndices: [Int]
    /// Malformed records, in file order. Never rendered with vault values —
    /// index + reason only.
    public var malformedRows: [(index: Int, reason: String)]

    /// Creates a document; used by the parser.
    public init(
        headers: [String],
        rows: [[String]],
        rowIndices: [Int],
        malformedRows: [(index: Int, reason: String)]
    ) {
        self.headers = headers
        self.rows = rows
        self.rowIndices = rowIndices
        self.malformedRows = malformedRows
    }

    public static func == (lhs: CSVDocument, rhs: CSVDocument) -> Bool {
        lhs.headers == rhs.headers
            && lhs.rows == rhs.rows
            && lhs.rowIndices == rhs.rowIndices
            && lhs.malformedRows.count == rhs.malformedRows.count
            && zip(lhs.malformedRows, rhs.malformedRows).allSatisfy {
                $0.index == $1.index && $0.reason == $1.reason
            }
    }
}

/// RFC 4180 CSV parsing (05-RESEARCH R-4, D-14: format logic lives in the
/// open-source core; zero dependencies, pure function over `Data`).
///
/// Pinned semantics (T-05-06 vectors):
/// - UTF-8 text with a leading `EF BB BF` BOM stripped before decode; bytes
///   that are not valid UTF-8 throw `InteropError.csvUnreadable`.
/// - `,` separates fields; fields may be double-quoted; `""` inside a quoted
///   field is a literal quote; commas and line breaks inside quotes are
///   literal content.
/// - CRLF, CR, and LF all terminate a record.
/// - Malformed records (field count mismatch against the header, unclosed
///   quote, content after a closing quote) are collected into
///   `CSVDocument.malformedRows` — the parse continues.
/// - An empty file (no bytes, only line breaks, or a single blank record)
///   throws `InteropError.emptyFile`.
///
/// One deliberate leniency, documented here: a quote appearing inside an
/// UNQUOTED field is treated as a literal character (spreadsheet-export
/// reality beats strict RFC rejection, and the row's field count still gets
/// validated against the header). Completely blank lines carry no record and
/// are skipped.
public enum CSV {

    /// Parses CSV bytes into a `CSVDocument`. The source data is read-only
    /// input — the parser never writes (the app-layer import reads the file
    /// exactly once and never modifies it).
    public static func parse(_ data: Data) throws -> CSVDocument {
        // BOM strip before decode (05-RESEARCH pitfall 4: Google exports
        // carry a BOM; leaving it would corrupt the first header name).
        var payload = data
        if payload.starts(with: [0xEF, 0xBB, 0xBF]) {
            payload = payload.dropFirst(3)
        }
        guard let text = String(data: payload, encoding: .utf8) else {
            throw InteropError.csvUnreadable
        }

        var records: [(fields: [String], malformed: String?)] = []
        var fields: [String] = []
        var field = ""
        var quoted = false      // inside a "..." section
        var afterQuote = false  // a quote just closed — only , \r \n or EOF may follow
        var rowMalformed: String?
        var rowHasContent = false

        func endField() {
            fields.append(field)
            field = ""
            afterQuote = false
        }

        func endRow() {
            endField()
            // A record is only real when it carried at least one character
            // (blank lines are skipped; the trailing newline at EOF adds no
            // record).
            if rowHasContent {
                records.append((fields, rowMalformed))
            }
            fields = []
            rowMalformed = nil
            rowHasContent = false
        }

        let chars = Array(text)
        var i = 0
        while i < chars.count {
            let ch = chars[i]
            // A line break OUTSIDE quotes is a record terminator, not record
            // content — a completely blank line must not become a record.
            // Note: Swift grapheme clustering folds CRLF into ONE Character,
            // so the terminator cases below match "\r\n", "\r", and "\n".
            if quoted || (ch != "\r" && ch != "\n" && ch != "\r\n") {
                rowHasContent = true
            }
            if quoted {
                if ch == "\"" {
                    if i + 1 < chars.count, chars[i + 1] == "\"" {
                        field.append("\"") // "" → literal quote
                        i += 1
                    } else {
                        quoted = false
                        afterQuote = true
                    }
                } else {
                    field.append(ch) // commas/newlines are literal inside quotes
                }
            } else if afterQuote {
                if ch == "," {
                    endField()
                } else if ch == "\r" || ch == "\n" || ch == "\r\n" {
                    endRow()
                } else {
                    // Content after a closing quote ("a"b) — malformed row,
                    // leniently continued as literal text so the rest of the
                    // file still parses.
                    if rowMalformed == nil {
                        rowMalformed = "unexpected characters after a closing quote"
                    }
                    field.append(ch)
                    afterQuote = false
                }
            } else {
                switch ch {
                case ",":
                    endField()
                case "\r\n", "\r", "\n":
                    endRow()
                case "\"":
                    if field.isEmpty {
                        quoted = true
                    } else {
                        // Lenient: a quote inside an unquoted field is a
                        // literal character (see type comment).
                        field.append(ch)
                    }
                default:
                    field.append(ch)
                }
            }
            i += 1
        }
        if rowHasContent || !fields.isEmpty || !field.isEmpty {
            if quoted {
                // EOF inside an open quote — the record never closed.
                if rowMalformed == nil {
                    rowMalformed = "unclosed quoted field"
                }
            }
            endRow()
        }

        // Empty-file guard: no records at all, or only blank records
        // (whitespace-only file) — nothing to map or preview.
        func isBlank(_ record: (fields: [String], malformed: String?)) -> Bool {
            record.malformed == nil
                && record.fields.count == 1
                && record.fields[0].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        let meaningful = records.enumerated().filter { !isBlank($1) }
        guard let headerRecord = meaningful.first else {
            throw InteropError.emptyFile
        }

        let headers = headerRecord.element.fields
        var rows: [[String]] = []
        var rowIndices: [Int] = []
        var malformedRows: [(index: Int, reason: String)] = []
        if let headerReason = headerRecord.element.malformed {
            malformedRows.append((headerRecord.offset, headerReason))
        }
        for (index, record) in meaningful.dropFirst() {
            if let reason = record.malformed {
                malformedRows.append((index, reason))
            } else if record.fields.count != headers.count {
                malformedRows.append((
                    index,
                    "expected \(headers.count) fields, got \(record.fields.count)"))
            } else {
                rows.append(record.fields)
                rowIndices.append(index)
            }
        }
        return CSVDocument(
            headers: headers, rows: rows, rowIndices: rowIndices,
            malformedRows: malformedRows)
    }
}
