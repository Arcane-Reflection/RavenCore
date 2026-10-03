import CryptoKit
import XCTest
@testable import RavenCore

/// Common-password corpus fidelity suite (Phase 8, plan 08-01B; EXTRA-02).
/// The vendored SecLists top-10k resource is pinned byte-for-byte before any
/// HealthIndex code trusts it — the same discipline as `GeneratorTests` for
/// the EFF wordlist (04-CONTEXT D-08 precedent) and `Bip39Tests` (02-CONTEXT
/// D-08): a diff here is a deliberate re-pin of the vendor source.
final class CommonPasswordListTests: XCTestCase {

    // MARK: - Corpus integrity pin (T-08-05)

    /// The committed resource pins this SHA-256 — the verbatim `head -n 10000`
    /// prefix of SecLists xato-net-10-million-passwords.txt at the commit
    /// recorded in the `CommonPasswordList` doc comment.
    static let corpusSHA256 = "c63d5e4ccc31344d662583cc39ca4bd5bd20517ff1d24501f0c4e0c22d9b722a"
    static let expectedLineCount = 10_000

    func testCorpusResourceIsPinned() throws {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "common-passwords-top10k", withExtension: "txt"))
        let data = try Data(contentsOf: url)
        let sha256 = Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(
            sha256,
            Self.corpusSHA256,
            "common-passwords-top10k.txt changed — re-pin the SecLists source deliberately")
        // Exact line count in `wc -l` semantics (LF bytes — the extraction
        // command's contract), so the upstream blank line stays counted.
        XCTAssertEqual(
            data.filter { $0 == UInt8(ascii: "\n") }.count,
            Self.expectedLineCount)
    }

    func testCorpusLoadsAndMeetsContract() throws {
        XCTAssertNoThrow(try CommonPasswordList.validateResource())
        XCTAssertEqual(
            CommonPasswordList.expectedLineCount, 10_000,
            "the module constant must match the pinned resource")
        // Membership sanity on both ends of the frequency-sorted list. The
        // upstream prefix carries one blank line (upstream data, kept
        // verbatim), so the deduplicated password set holds 9,999 entries.
        XCTAssertEqual(CommonPasswordList.passwords.count, 9_999)
        XCTAssertEqual(Set(CommonPasswordList.passwords).count, 9_999, "no duplicates")
        XCTAssertTrue(CommonPasswordList.contains("password"))
        XCTAssertTrue(CommonPasswordList.contains("letmein"))
        XCTAssertFalse(
            CommonPasswordList.contains("correct horse battery staple zzz"),
            "a high-entropy passphrase is not in the top-10k corpus")
    }

    // MARK: - Load-time validation (testable directly per plan Test 5)

    private func syntheticCorpus(lineCount: Int, duplicate: Bool = false) -> Data {
        var lines: [String] = []
        for index in 0..<(duplicate ? lineCount - 1 : lineCount) {
            lines.append("pw-\(index)")
        }
        if duplicate { lines.append("pw-0") }
        return Data(lines.joined(separator: "\n").utf8) + Data("\n".utf8)
    }

    func testValidationRejectsWrongLineCount() {
        XCTAssertThrowsError(try CommonPasswordList.validate(syntheticCorpus(lineCount: 9_999)))
        XCTAssertThrowsError(try CommonPasswordList.validate(syntheticCorpus(lineCount: 10_001)))
    }

    func testValidationRejectsDuplicateBearingContent() {
        XCTAssertThrowsError(
            try CommonPasswordList.validate(syntheticCorpus(lineCount: 10_000, duplicate: true)),
            "a duplicate entry breaks the one-password-per-line corpus contract")
    }

    func testValidationRejectsCRAndBOM() {
        var crData = syntheticCorpus(lineCount: 10_000)
        crData[10] = UInt8(ascii: "\r")
        XCTAssertThrowsError(try CommonPasswordList.validate(crData), "no CR allowed")

        var bomData = syntheticCorpus(lineCount: 10_000)
        bomData.insert(contentsOf: [0xEF, 0xBB, 0xBF], at: 0)
        XCTAssertThrowsError(try CommonPasswordList.validate(bomData), "no BOM allowed")
    }

    func testValidationToleratesUpstreamBlankLine() throws {
        // The real upstream prefix contains exactly one blank line (kept
        // verbatim); validation counts it toward the 10,000 lines but never
        // treats it as a password.
        var lines = (0..<9_999).map { "pw-\($0)" }
        lines.insert("", at: 42)
        let data = Data(lines.joined(separator: "\n").utf8) + Data("\n".utf8)
        let passwords = try CommonPasswordList.validate(data)
        XCTAssertEqual(passwords.count, 9_999)
        XCTAssertFalse(passwords.contains(""))
    }

    func testValidationAcceptsWellFormedCorpus() throws {
        XCTAssertNoThrow(try CommonPasswordList.validate(syntheticCorpus(lineCount: 10_000)))
    }
}
