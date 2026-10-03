import CryptoKit
import XCTest
@testable import RavenCore

/// Password generator suite (Phase 4, plan 04-02; VAULT-03). Task 04-02-01
/// lands the wordlist fidelity half FIRST — the vendored EFF resource is
/// pinned byte-for-byte before any generator code exists (04-CONTEXT D-08).
final class GeneratorTests: XCTestCase {

    // MARK: - Wordlist fidelity (04-02-01, T-04-06)

    /// The committed resource pins this SHA-256 — a diff here is a
    /// deliberate format re-pin of the vendor source.
    static let wordlistSHA256 = "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522"

    func testWordlistResourceIsPinned() throws {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "eff-large-wordlist", withExtension: "txt"))
        let data = try Data(contentsOf: url)
        let sha256 = Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(
            sha256,
            Self.wordlistSHA256,
            "eff-large-wordlist.txt changed — re-pin the vendor source deliberately")
    }

    func testWordlistLoadsAndMeetsContract() throws {
        XCTAssertNoThrow(try EffWordlist.validateResource())
        XCTAssertEqual(EffWordlist.words.count, 7776)
        XCTAssertEqual(Set(EffWordlist.words).count, 7776, "no duplicates")
        XCTAssertEqual(EffWordlist.words.first, "abacus")
        XCTAssertEqual(EffWordlist.words.last, "zoom")
        XCTAssertEqual(EffWordlist.wordCount, 7776)
    }

    func testWordlistIsPureLowercaseASCII() {
        for word in EffWordlist.words {
            XCTAssertFalse(word.isEmpty, word)
            XCTAssertTrue(word.allSatisfy { ($0.isASCII && $0.isLowercase) || $0 == "-" }, word)
        }
    }

    // MARK: - Generator constraints (04-02-02, T-04-04)

    func testRandomModeRespectsLengthAndCharset() throws {
        var config = PasswordGenerator.Config()
        config.mode = .characters
        for length in [12, 20, 37, 64] {
            config.length = length
            let password = try PasswordGenerator.generate(config: config)
            XCTAssertEqual(password.count, length)
            XCTAssertTrue(password.allSatisfy { config.charset.contains($0) })
        }
    }

    func testEveryEnabledGroupAppears() throws {
        var config = PasswordGenerator.Config()
        config.mode = .characters
        config.length = 12
        for _ in 0..<25 {
            let password = try PasswordGenerator.generate(config: config)
            XCTAssertTrue(password.contains(where: { $0.isLowercase }), password)
            XCTAssertTrue(password.contains(where: { $0.isUppercase }), password)
            XCTAssertTrue(password.contains(where: { $0.isNumber }), password)
            XCTAssertTrue(password.contains(where: { "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".contains($0) }), password)
        }
    }

    func testSubsetCharsetRestrictsOutput() throws {
        var config = PasswordGenerator.Config()
        config.mode = .characters
        config.useUppercase = false
        config.useDigits = false
        config.useSymbols = false
        let password = try PasswordGenerator.generate(config: config)
        XCTAssertTrue(password.allSatisfy { $0.isLowercase && $0.isASCII })
        XCTAssertFalse(config.hasCharset == false)
    }

    func testAllGroupsDisabledThrows() throws {
        var config = PasswordGenerator.Config()
        config.mode = .characters
        config.useLowercase = false
        config.useUppercase = false
        config.useDigits = false
        config.useSymbols = false
        XCTAssertThrowsError(try PasswordGenerator.generate(config: config)) { error in
            XCTAssertEqual(error as? PasswordGenerator.PasswordGeneratorError, .invalidConfiguration)
        }
        XCTAssertEqual(PasswordGenerator.entropyBits(config: config), 0)
    }

    func testPassphraseModeUsesWordlistDomainAndSeparator() throws {
        var config = PasswordGenerator.Config()
        config.mode = .passphrase
        config.wordCount = 6
        let words = Set(EffWordlist.words)
        for _ in 0..<10 {
            let phrase = try PasswordGenerator.generate(config: config)
            let parts = phrase.components(separatedBy: ".")
            XCTAssertEqual(parts.count, 6)
            for part in parts {
                XCTAssertTrue(words.contains(part), part)
            }
        }
    }

    func testEntropyValuesAreExact() {
        var random = PasswordGenerator.Config()
        random.mode = .characters
        random.length = 20 // full 94-char set (lower+upper+10 digits+26 symbols)
        XCTAssertEqual(random.charset.count, 94)
        XCTAssertEqual(
            PasswordGenerator.entropyBits(config: random),
            20 * log2(94), accuracy: 0.01)

        var phrase = PasswordGenerator.Config()
        phrase.mode = .passphrase
        phrase.wordCount = 6
        XCTAssertEqual(
            PasswordGenerator.entropyBits(config: phrase),
            6 * log2(7776), accuracy: 0.01)
        XCTAssertEqual(6 * log2(7776), 77.55, accuracy: 0.01)
    }

    func testBoundsAreClamped() throws {
        var config = PasswordGenerator.Config()
        config.mode = .characters
        config.length = 11
        XCTAssertEqual(try PasswordGenerator.generate(config: config).count, 12)
        config.length = 65
        XCTAssertEqual(try PasswordGenerator.generate(config: config).count, 64)

        config.mode = .passphrase
        config.wordCount = 2
        XCTAssertEqual(try PasswordGenerator.generate(config: config).components(separatedBy: ".").count, 3)
        config.wordCount = 11
        XCTAssertEqual(try PasswordGenerator.generate(config: config).components(separatedBy: ".").count, 10)
    }

    func testUnbiasedIndexStaysInBoundsAndDoesNotDegenerate() {
        // Binary choice over a large sample: the residue-rejection path must
        // stay near 50/50 (a modulo-biased implementation drifts badly).
        var zeros = 0
        for _ in 0..<2_000 where PasswordGenerator.unbiasedIndex(bound: 2) == 0 {
            zeros += 1
        }
        XCTAssertEqual(Double(zeros) / 2_000, 0.5, accuracy: 0.06)
        // Bounds never violated.
        for bound in [1, 2, 3, 7776] {
            for _ in 0..<50 {
                let index = PasswordGenerator.unbiasedIndex(bound: bound)
                XCTAssertGreaterThanOrEqual(index, 0)
                XCTAssertLessThan(index, bound)
            }
        }
    }

    func testWordFrequenciesDoNotCollapse() throws {
        var config = PasswordGenerator.Config()
        config.mode = .passphrase
        var firstWords = Set<String>()
        for _ in 0..<30 {
            let phrase = try PasswordGenerator.generate(config: config)
            firstWords.insert(String(phrase.split(separator: ".").first!))
        }
        XCTAssertGreaterThan(firstWords.count, 3, "30 draws should surface multiple distinct first words")
    }
}
