import Foundation

/// The CSV → vault column mapper (VAULT-05 engine half, 05-CONTEXT D-09).
///
/// Responsibilities, all pure functions over parsed `CSVDocument` values:
/// - `detectMapping` matches header names against the official Bitwarden and
///   Chrome/Google Passwords export column sets (05-RESEARCH R-4) — exact
///   match on lowercased+trimmed header text; the FIRST matching column wins
///   per target (one column per target, "name" appearing twice resolves to
///   the first). Unmatched targets are `nil` — the preview's manual Picker
///   fills them (D-09: auto-detect + manual adjustment).
/// - `mapRows` materializes rows into `CsvRowRecord`s: an empty title falls
///   back to the URL, then to "(untitled)"; TOTP cells go through
///   `otpauthSecret` (URI → secret parameter, bare value verbatim); every
///   fallback or repair sets `flagged` so the preview can surface it — no
///   whole-row skips for data a human can confirm.
///
/// Values are carried verbatim: no trimming, unescaping, or rewriting of
/// field content beyond the documented title/TOTP fallbacks.
public enum VaultCSVMapper {

    // MARK: - Mapping targets (D-09: the six-field contract)

    /// The six import targets (success criterion 3). Raw values match the
    /// record field names; display names live in the app's strings table.
    public enum Target: String, Sendable, CaseIterable {
        case title
        case username
        case password
        case url
        case notes
        case totp
    }

    // MARK: - Header detection

    /// Known header aliases per target — the official export column names
    /// (Bitwarden: folder/favorite/type/name/notes/fields/reprompt/login_uri/
    /// login_username/login_password/login_totp; Chrome/Google Passwords:
    /// name/url/username/password/note). Matching is exact after lowercasing
    /// and trimming; the BOM is already gone at parse time.
    private static let aliases: [Target: Set<String>] = [
        .title: ["name"],
        .username: ["login_username", "username"],
        .password: ["login_password", "password"],
        .url: ["login_uri", "url"],
        .notes: ["notes", "note"],
        .totp: ["login_totp"],
    ]

    /// Detects the column mapping from a document's header record. Every
    /// target key is present; an unmatched target maps to `nil` (the manual
    /// Picker path). Two dialects never collide: their shared names ("name")
    /// map to the same target, and dialect-specific names are disjoint.
    public static func detectMapping(headers: [String]) -> [Target: Int?] {
        let normalized = headers.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        var result: [Target: Int?] = [:]
        for target in Target.allCases {
            let accepted = aliases[target] ?? []
            // First exact match wins — one column per target (D-09). The
            // explicit `.some(...)` keeps unmatched targets as key→nil
            // instead of removing the key (dictionary-of-optionals trap).
            if let index = normalized.firstIndex(where: { accepted.contains($0) }) {
                result[target] = .some(index)
            } else {
                result[target] = .some(nil)
            }
        }
        return result
    }

    // MARK: - Row mapping

    /// Maps the document's well-formed rows through `mapping` (as produced
    /// by `detectMapping`, optionally adjusted by the user). Malformed rows
    /// never reach here — they ride `CSVDocument.malformedRows` into the
    /// report.
    public static func mapRows(
        document: CSVDocument,
        mapping: [Target: Int?]
    ) -> [CsvRowRecord] {
        var records: [CsvRowRecord] = []
        // `rowIndices` carries each row's source record ordinal (header = 0,
        // first data record = 1 — the same stream `malformedRows` counts). A
        // malformed record earlier in the file must not drag later rows'
        // `sourceRow` below their true position (enumerating `rows` alone
        // would).
        for (recordIndex, row) in zip(document.rowIndices, document.rows) {
            func field(_ target: Target) -> String {
                guard let column = mapping[target] ?? nil,
                      row.indices.contains(column) else { return "" }
                return row[column]
            }

            let url = field(.url)
            var title = field(.title)
            var flagged = false
            if title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                // Empty title → URL fallback → "(untitled)" — always flagged
                // so the preview surfaces the substitution.
                title = url.trimmingCharacters(in: .whitespacesAndNewlines)
                if title.isEmpty { title = "(untitled)" }
                flagged = true
            }

            var totpSecret: String?
            let rawTotp = field(.totp)
            let trimmedTotp = rawTotp.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmedTotp.isEmpty {
                if trimmedTotp.lowercased().hasPrefix("otpauth://") {
                    // A full otpauth URI is stored VERBATIM — strict validity
                    // decides only whether the engine can GENERATE from it
                    // (out-of-domain parameters land in the honest
                    // "TOTP unavailable" state), never whether the data
                    // survives (261003-mk7 fourth pass: the bare-secret
                    // fallback served RFC-default codes for 5-digit/Steam
                    // entries).
                    totpSecret = trimmedTotp
                } else if let secret = otpauthSecret(from: rawTotp) {
                    totpSecret = secret
                } else {
                    // Defensively unreachable (fifth-pass review): a
                    // non-empty non-URI value always yields a bare secret
                    // from `otpauthSecret` — kept so a future branch reorder
                    // cannot silently drop data.
                    flagged = true
                }
            }

            records.append(CsvRowRecord(
                title: title,
                username: field(.username),
                password: field(.password),
                url: url.isEmpty ? nil : url,
                notes: field(.notes),
                totpSecret: totpSecret,
                sourceRow: recordIndex,
                flagged: flagged))
        }
        return records
    }

    // MARK: - TOTP extraction

    /// Extracts the stored TOTP secret from a `login_totp`-style cell — a
    /// thin wrapper over `OTPAuthURIParser.secret(in:)` (06-02 D-07 hoist;
    /// the parser now also returns the full generation parameter set for
    /// live codes). Behavior is byte-identical to the pre-hoist
    /// implementation: an `otpauth://…` URI yields its `secret` query
    /// parameter, any other non-blank value is a bare secret (surrounding
    /// whitespace trimmed, content verbatim), and a URI without a usable
    /// secret parameter returns nil — the caller flags the row rather than
    /// skipping it.
    public static func otpauthSecret(from value: String) -> String? {
        OTPAuthURIParser.secret(in: value)
    }
}

/// One mapped CSV row — everything a record import needs, without any
/// document context. `sourceRow` is the record's index in the source file
/// (header record = 0, first data record = 1) so reports can name rows
/// honestly.
public struct CsvRowRecord: Sendable, Equatable {
    public var title: String
    public var username: String
    public var password: String
    public var url: String?
    public var notes: String
    /// Extracted TOTP secret — stored only, never used to generate codes
    /// in v1 (Phase 6 AUTO-02 owns live codes).
    public var totpSecret: String?
    public var sourceRow: Int
    /// `true` when a fallback or repair happened that the preview must
    /// surface (substituted title, unreadable TOTP value) — never silent.
    public var flagged: Bool

    /// Creates a mapped row; used by the mapper.
    public init(
        title: String,
        username: String,
        password: String,
        url: String?,
        notes: String,
        totpSecret: String?,
        sourceRow: Int,
        flagged: Bool
    ) {
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.totpSecret = totpSecret
        self.sourceRow = sourceRow
        self.flagged = flagged
    }
}
