import XCTest
@testable import RavenCore

/// RFC 4180 parser vectors + Bitwarden/Chrome column-mapping table tests
/// (VAULT-05 engine half, 05-CONTEXT D-09/D-14, success criterion 3).
/// Expected values mirror Tests/Fixtures/CSV — the fixtures are the
/// canonical pinned samples of the official export formats.
final class CsvTests: XCTestCase {

    static let csvDirectory: URL = URL(fileURLWithPath: TestFixtures.packageRoot)
        .appendingPathComponent("Tests/Fixtures/CSV")

    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: Self.csvDirectory.appendingPathComponent(name))
    }

    private func parse(_ text: String) throws -> CSVDocument {
        try CSV.parse(Data(text.utf8))
    }

    /// Flattens the dictionary-of-optionals subscript (`Int??` → `Int?`).
    private func col(
        _ target: VaultCSVMapper.Target,
        _ mapping: [VaultCSVMapper.Target: Int?]
    ) -> Int? {
        mapping[target] ?? nil
    }

    private func detect(_ headers: [String]) -> [VaultCSVMapper.Target: Int?] {
        VaultCSVMapper.detectMapping(headers: headers)
    }

    // MARK: - Parser vectors (T-05-06)

    func testQuotedCommaAndEscapedQuotes() throws {
        let document = try parse("name,note\n\"Site, Inc\",\"said \"\"hi\"\"\"\n")
        XCTAssertEqual(document.headers, ["name", "note"])
        XCTAssertEqual(document.rows, [["Site, Inc", "said \"hi\""]])
        XCTAssertTrue(document.malformedRows.isEmpty)
    }

    func testQuotedLineBreaksAreLiteral() throws {
        let document = try parse("name,note\n\"multi\nline\",\"kept\"\n")
        XCTAssertEqual(document.headers, ["name", "note"])
        XCTAssertEqual(document.rows, [["multi\nline", "kept"]])
        XCTAssertTrue(document.malformedRows.isEmpty)
    }

    func testLineEndingVariantsProduceIdenticalDocuments() throws {
        let crlf = try parse("a,b\r\n1,2\r\n3,4\r\n")
        let cr = try parse("a,b\r1,2\r3,4\r")
        let lf = try parse("a,b\n1,2\n3,4\n")
        let mixed = try parse("a,b\n1,2\r\n3,4\r")

        XCTAssertEqual(crlf.rows, [["1", "2"], ["3", "4"]])
        XCTAssertEqual(crlf, cr)
        XCTAssertEqual(crlf, lf)
        XCTAssertEqual(crlf, mixed)
    }

    func testUtf8BomIsStrippedBeforeDecode() throws {
        let plain = try parse("name,url\nSite,https://x\n")
        let withBOM = try CSV.parse(Data([0xEF, 0xBB, 0xBF]) + Data("name,url\nSite,https://x\n".utf8))
        XCTAssertEqual(withBOM, plain, "BOM must not reach the header names")
        XCTAssertEqual(withBOM.headers.first, "name")
    }

    func testMalformedColumnCountsAreCollectedWithoutAborting() throws {
        let document = try parse("a,b,c\n1,2\n3,3,3\n4,4,4,4\n")
        XCTAssertEqual(document.rows, [["3", "3", "3"]], "only the well-formed row imports")
        XCTAssertEqual(document.malformedRows.count, 2)
        XCTAssertEqual(document.malformedRows[0].index, 1)
        XCTAssertEqual(document.malformedRows[0].reason, "expected 3 fields, got 2")
        XCTAssertEqual(document.malformedRows[1].index, 3)
        XCTAssertEqual(document.malformedRows[1].reason, "expected 3 fields, got 4")
    }

    func testUnclosedQuoteIsCollectedAtEndOfFile() throws {
        let document = try parse("a,b\n1,2\n\"never closed,3\n")
        XCTAssertEqual(document.rows, [["1", "2"]])
        XCTAssertEqual(document.malformedRows.count, 1)
        XCTAssertEqual(document.malformedRows[0].index, 2)
        XCTAssertEqual(document.malformedRows[0].reason, "unclosed quoted field")
    }

    func testContentAfterClosingQuoteIsCollected() throws {
        let document = try parse("a,b\n\"x\"y,2\n3,4\n")
        XCTAssertEqual(document.rows, [["3", "4"]], "the malformed row is excluded, parsing continues")
        XCTAssertEqual(document.malformedRows.count, 1)
        XCTAssertEqual(document.malformedRows[0].index, 1)
        XCTAssertEqual(document.malformedRows[0].reason, "unexpected characters after a closing quote")
    }

    func testBlankLinesAreSkippedAndTrailingNewlineAddsNoRecord() throws {
        let document = try parse("a,b\n\n1,2\n\n3,4\n")
        XCTAssertEqual(document.rows, [["1", "2"], ["3", "4"]])
        XCTAssertTrue(document.malformedRows.isEmpty)
    }

    func testEmptyFileThrowsEmptyFile() {
        for input in [Data(), Data("\n".utf8), Data("\n\n".utf8), Data("   \n  \n".utf8)] {
            XCTAssertThrowsError(try CSV.parse(input), "input \(input)") { error in
                XCTAssertEqual(error as? InteropError, .emptyFile)
            }
        }
    }

    func testNonUtf8BytesThrowCsvUnreadable() {
        XCTAssertThrowsError(try CSV.parse(Data([0xFF, 0xFE, 0xFD]))) { error in
            XCTAssertEqual(error as? InteropError, .csvUnreadable)
        }
    }

    func testHeaderOnlyDocumentHasZeroRows() throws {
        let document = try parse("name,url,username\n")
        XCTAssertEqual(document.headers, ["name", "url", "username"])
        XCTAssertTrue(document.rows.isEmpty)
        XCTAssertTrue(document.malformedRows.isEmpty)
    }

    // MARK: - Header detection (D-09)

    func testBitwardenFixtureDetectsAllSixTargets() throws {
        let document = try CSV.parse(try fixture("bitwarden-sample.csv"))
        XCTAssertEqual(document.headers.count, 11)
        let mapping = detect(document.headers)
        XCTAssertEqual(col(.title, mapping), 3)
        XCTAssertEqual(col(.username, mapping), 8)
        XCTAssertEqual(col(.password, mapping), 9)
        XCTAssertEqual(col(.url, mapping), 7)
        XCTAssertEqual(col(.notes, mapping), 4)
        XCTAssertEqual(col(.totp, mapping), 10)
    }

    func testChromeFixtureDetectsFiveTargetsTotpUnmatched() throws {
        let document = try CSV.parse(try fixture("chrome-sample.csv"))
        let mapping = detect(document.headers)
        XCTAssertEqual(col(.title, mapping), 0)
        XCTAssertEqual(col(.username, mapping), 2)
        XCTAssertEqual(col(.password, mapping), 3)
        XCTAssertEqual(col(.url, mapping), 1)
        XCTAssertEqual(col(.notes, mapping), 4)
        XCTAssertNil(col(.totp, mapping), "Chrome has no TOTP column — manual Picker path")
    }

    func testUnknownHeadersReturnNilForEveryTarget() throws {
        let mapping = detect(["col1", "col2", "col3"])
        for target in VaultCSVMapper.Target.allCases {
            XCTAssertNotNil(mapping[target], "\(target) key must stay present (key→nil)")
            XCTAssertNil(col(target, mapping), "\(target) must be unmatched for unknown headers")
        }
    }

    func testHeaderMatchingIsCaseAndWhitespaceInsensitive() throws {
        let mapping = detect([" NAME ", "login_uri", "LOGIN_USERNAME", "Login_Password", "Notes", "LOGIN_TOTP"])
        XCTAssertEqual(col(.title, mapping), 0)
        XCTAssertEqual(col(.url, mapping), 1)
        XCTAssertEqual(col(.username, mapping), 2)
        XCTAssertEqual(col(.password, mapping), 3)
        XCTAssertEqual(col(.notes, mapping), 4)
        XCTAssertEqual(col(.totp, mapping), 5)
    }

    func testDuplicateColumnNamesResolveToFirstMatch() throws {
        let mapping = detect(["name", "name", "username"])
        XCTAssertEqual(col(.title, mapping), 0, "first exact match wins — one column per target")
    }

    // MARK: - Row mapping (success criterion 3, engine evidence)

    func testBitwardenFixtureMapsAllSixFieldsPerValue() throws {
        let document = try CSV.parse(try fixture("bitwarden-sample.csv"))
        let records = VaultCSVMapper.mapRows(document: document, mapping: detect(document.headers))
        XCTAssertEqual(records.count, 3)

        let github = records[0]
        XCTAssertEqual(github.title, "GitHub")
        XCTAssertEqual(github.username, "alice")
        XCTAssertEqual(github.password, "pw-github-1")
        XCTAssertEqual(github.url, "https://github.com")
        XCTAssertEqual(github.notes, "Dev account, primary")
        XCTAssertEqual(github.totpSecret, "JBSWY3DPEHPK3PXP", "otpauth URI → secret parameter")
        XCTAssertEqual(github.sourceRow, 1)
        XCTAssertFalse(github.flagged)

        XCTAssertEqual(records[1].notes, "Notes with \"quoted\" words", "escaped quotes decode")
        XCTAssertNil(records[1].totpSecret, "empty TOTP cell → nil, not flagged")
        XCTAssertFalse(records[1].flagged)

        XCTAssertEqual(records[2].totpSecret, "JBSWY3DPEHPK3PXPUZRQ", "bare secret stored verbatim")
        XCTAssertFalse(records[2].flagged)
    }

    func testChromeFixtureMapsValues() throws {
        let document = try CSV.parse(try fixture("chrome-sample.csv"))
        let records = VaultCSVMapper.mapRows(document: document, mapping: detect(document.headers))
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[0].title, "Example Site")
        XCTAssertEqual(records[0].username, "dana")
        XCTAssertEqual(records[0].password, "pw-dana-1")
        XCTAssertEqual(records[0].url, "https://example.com")
        XCTAssertEqual(records[0].notes, "first note")
        XCTAssertEqual(records[1].notes, "note with, comma")
    }

    func testOtpauthFixtureUriAndBareSecretAndUnreadableFlag() throws {
        let document = try CSV.parse(try fixture("otpauth.csv"))
        var mapping = detect(document.headers)
        XCTAssertNil(col(.totp, mapping), "custom totp header needs the manual Picker path")
        mapping[.totp] = .some(5) // manual remap
        let records = VaultCSVMapper.mapRows(document: document, mapping: mapping)

        XCTAssertEqual(records[0].totpSecret, "KRMVATZTJF6UC55V", "URI secret extracted; issuer/period/digits dropped")
        XCTAssertFalse(records[0].flagged)
        XCTAssertEqual(records[1].totpSecret, "JBSWY3DPEHPK3PXPUZRQ", "bare secret stored verbatim")
        XCTAssertFalse(records[1].flagged)
        XCTAssertNil(records[2].totpSecret, "URI without secret parameter → nil")
        XCTAssertTrue(records[2].flagged, "unreadable TOTP flags the row — never a silent drop")
    }

    func testOtpauthSecretUnitBehavior() {
        XCTAssertEqual(
            VaultCSVMapper.otpauthSecret(from: "otpauth://totp/acme?secret=ABC234&period=30&digits=8&issuer=Acme"),
            "ABC234")
        XCTAssertEqual(VaultCSVMapper.otpauthSecret(from: "  PLAINSECRET  "), "PLAINSECRET")
        XCTAssertNil(VaultCSVMapper.otpauthSecret(from: "otpauth://totp/nosecret?period=30"))
        XCTAssertNil(VaultCSVMapper.otpauthSecret(from: "   "))
    }

    func testEmptyTitleFallsBackToUrlThenUntitled() throws {
        let document = try parse("name,url,username,password,note\n,https://byurl.example,u,p,\n,,,,\n")
        let records = VaultCSVMapper.mapRows(
            document: document, mapping: detect(document.headers))
        XCTAssertEqual(records[0].title, "https://byurl.example", "empty title → URL fallback")
        XCTAssertTrue(records[0].flagged)
        XCTAssertEqual(records[1].title, "(untitled)", "no URL either → placeholder title")
        XCTAssertTrue(records[1].flagged)
        XCTAssertEqual(records[1].sourceRow, 2)
    }

    func testUnmappedTargetsImportAsEmptyOptionalFields() throws {
        let document = try CSV.parse(try fixture("chrome-sample.csv"))
        let records = VaultCSVMapper.mapRows(document: document, mapping: detect(document.headers))
        XCTAssertNil(records[0].totpSecret, "unmatched target imports as nil (empty), never a placeholder string")
    }

    // MARK: - Malformed fixture (report shape the app layer surfaces)

    func testMalformedFixtureCollectsExactIndicesAndReasons() throws {
        let document = try CSV.parse(try fixture("malformed.csv"))
        XCTAssertEqual(document.rows.count, 2, "the two well-formed rows survive")
        XCTAssertEqual(document.rows[0].first, "Good Site")
        XCTAssertEqual(document.rows[1].first, "Another Good")
        XCTAssertEqual(document.malformedRows.map(\.index), [2, 4])
        XCTAssertEqual(document.malformedRows[0].reason, "expected 5 fields, got 3")
        XCTAssertEqual(document.malformedRows[1].reason, "unclosed quoted field")
    }
}
