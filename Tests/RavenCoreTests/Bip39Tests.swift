import XCTest
@testable import RavenCore

/// TREZOR official BIP39 vectors, vendored at Tests/Fixtures/Bip39/ (PITFALL
/// #12 pattern: single source of truth on disk, no Swift literal copies).
struct TrezorVectorFile: Decodable {
    struct Source: Decodable {
        let url: String
        let commit: String
        let license: String
    }
    struct Vector: Decodable {
        let entropy: String
        let mnemonic: String
        let passphrase: String
        let seed: String

        var words: [String] { mnemonic.split(separator: " ").map(String.init) }
        var entropyData: Data { Data(hexDecoded: entropy) }
        var seedData: Data { Data(hexDecoded: seed) }
    }
    let source: Source
    let vectors: [Vector]
}

final class Bip39Tests: XCTestCase {

    // MARK: - Fixture access

    static let vectorsURL = URL(fileURLWithPath: TestFixtures.packageRoot)
        .appendingPathComponent("Tests/Fixtures/Bip39/trezor-english-vectors.json")

    static func loadVectors() throws -> TrezorVectorFile {
        guard FileManager.default.fileExists(atPath: vectorsURL.path) else {
            XCTFail("Missing \(vectorsURL.path) — the TREZOR vectors must stay committed (offline, vendored)")
            throw NSError(domain: "Bip39Tests", code: 1)
        }
        return try JSONDecoder().decode(TrezorVectorFile.self, from: Data(contentsOf: vectorsURL))
    }

    // MARK: - Wordlist fidelity (T-02-03)

    func testWordlistResourceFidelity() throws {
        // Asserts 2048 LF lines, no BOM/CR, strict [a-z], strictly sorted.
        try Bip39Wordlist.validateResource()

        XCTAssertEqual(Bip39Wordlist.english.count, 2048)
        XCTAssertEqual(Bip39Wordlist.english.first, "abandon")
        XCTAssertEqual(Bip39Wordlist.english.last, "zoo")
        // Index table agrees with list positions.
        XCTAssertEqual(Bip39Wordlist.englishIndices["abandon"], 0)
        XCTAssertEqual(Bip39Wordlist.englishIndices["zoo"], 2047)
    }

    // MARK: - All-zero 12-word tracer vector (fixture[0])

    func testAllZeroEntropyTwelveWordVector() throws {
        let vector = try Self.loadVectors().vectors[0]
        XCTAssertEqual(vector.entropy, String(repeating: "00", count: 16))

        let words = try Bip39.mnemonic(fromEntropy: vector.entropyData)
        XCTAssertEqual(words.count, 12)
        XCTAssertEqual(words, vector.words)
        XCTAssertEqual(words.last, "about")
        XCTAssertEqual(words.first, "abandon")

        let roundTripped = try Bip39.entropy(fromMnemonic: words)
        XCTAssertEqual(roundTripped, vector.entropyData)
        XCTAssertEqual(roundTripped, Data(repeating: 0, count: 16))

        let seed = try Bip39.seed(mnemonic: words, passphrase: vector.passphrase)
        XCTAssertEqual(seed, vector.seedData)
        // Cross-anchor from the plan: this vector's seed hex starts c55257c360c07c72.
        XCTAssertEqual(hexPrefix(seed, 8), "c55257c360c07c72")
    }

    func testVectorSourceRecorded() throws {
        let file = try Self.loadVectors()
        XCTAssertEqual(file.source.license, "MIT")
        XCTAssertFalse(file.source.commit.isEmpty)
        XCTAssertEqual(file.source.url, "https://github.com/trezor/python-mnemonic")
    }

    // MARK: - Full TREZOR vector sweep (T-02-01 / ROADMAP SC#3)

    func testFullVectorSweep() throws {
        let file = try Self.loadVectors()
        // Guard against silent fixture shrinkage: 8×12-word + 8×24-word.
        XCTAssertGreaterThanOrEqual(file.vectors.count, 12)
        let twelves = file.vectors.filter { $0.words.count == 12 }
        let twentyFours = file.vectors.filter { $0.words.count == 24 }
        XCTAssertGreaterThanOrEqual(twelves.count, 6)
        XCTAssertGreaterThanOrEqual(twentyFours.count, 6)

        for vector in file.vectors {
            // entropy → mnemonic, word-exact
            XCTAssertEqual(try Bip39.mnemonic(fromEntropy: vector.entropyData),
                           vector.words, vector.entropy)
            // mnemonic → entropy, byte-exact
            XCTAssertEqual(try Bip39.entropy(fromMnemonic: vector.words),
                           vector.entropyData, vector.mnemonic)
            // mnemonic + TREZOR passphrase → seed, byte-exact
            XCTAssertEqual(try Bip39.seed(mnemonic: vector.words, passphrase: vector.passphrase),
                           vector.seedData, vector.mnemonic)
        }
    }

    // MARK: - Negative matrix (typed errors, exact case)

    func testChecksumCorruptionRejected() throws {
        let file = try Self.loadVectors()
        let twelves = file.vectors.filter { $0.words.count == 12 }
        let twentyFours = file.vectors.filter { $0.words.count == 24 }

        // Swap a word inside the entropy region with a *different legal* word:
        // the phrase stays wordlist-clean but its checksum no longer verifies.
        for vector in [twelves[0], twentyFours[0]] {
            var corrupted = vector.words
            let replacement = corrupted[0] == "abandon" ? "ability" : "abandon"
            corrupted[0] = replacement
            XCTAssertThrowsError(try Bip39.validate(corrupted), vector.mnemonic) { error in
                XCTAssertEqual(error as? Bip39Error, .invalidChecksum)
            }
            XCTAssertThrowsError(try Bip39.entropy(fromMnemonic: corrupted)) { error in
                XCTAssertEqual(error as? Bip39Error, .invalidChecksum)
            }
        }
    }

    func testUnknownWordRejected() throws {
        let vector = try Self.loadVectors().vectors[0]
        var corrupted = vector.words
        corrupted[5] = "notaword"   // legal-looking token, absent from the list
        XCTAssertThrowsError(try Bip39.validate(corrupted)) { error in
            XCTAssertEqual(error as? Bip39Error, .unknownWord)
        }
    }

    func testWordCountOutsideTwelveOrTwentyFourRejected() throws {
        let vector = try Self.loadVectors().vectors[0]
        let words = vector.words    // 12 words

        // 11 words (legal words, truncated)
        XCTAssertThrowsError(try Bip39.validate(Array(words.dropLast()))) { error in
            XCTAssertEqual(error as? Bip39Error, .invalidWordCount)
        }
        // 13 words (legal words, appended)
        XCTAssertThrowsError(try Bip39.validate(words + ["zoo"])) { error in
            XCTAssertEqual(error as? Bip39Error, .invalidWordCount)
        }
        // 15 legal words — outside the module's exposed surface (D-07)
        XCTAssertThrowsError(try Bip39.validate(Array(repeating: "abandon", count: 15))) { error in
            XCTAssertEqual(error as? Bip39Error, .invalidWordCount)
        }
        // Empty input is also a count violation
        XCTAssertThrowsError(try Bip39.validate([])) { error in
            XCTAssertEqual(error as? Bip39Error, .invalidWordCount)
        }
    }

    func testEntropyLengthGuard() {
        XCTAssertThrowsError(try Bip39.mnemonic(fromEntropy: Data(repeating: 0, count: 20))) { error in
            XCTAssertEqual(error as? Bip39Error, .invalidEntropyLength)
        }
        XCTAssertThrowsError(try Bip39.mnemonic(fromEntropy: Data())) { error in
            XCTAssertEqual(error as? Bip39Error, .invalidEntropyLength)
        }
    }

    // MARK: - NFKD passphrase normalization

    func testNFKDNormalizesLigaturePassphrase() throws {
        let vector = try Self.loadVectors().vectors[0]
        // U+FB01 (ﬁ) must NFKD-decompose to "fi": both passphrases derive the
        // identical seed (self-contained proof NFKD runs on the passphrase).
        let ligature = try Bip39.seed(mnemonic: vector.words, passphrase: "\u{FB01}le")
        let plain = try Bip39.seed(mnemonic: vector.words, passphrase: "file")
        XCTAssertEqual(ligature, plain)
    }

    func testSeedDerivationIsDeterministic() throws {
        let vector = try Self.loadVectors().vectors[0]
        let first = try Bip39.seed(mnemonic: vector.words, passphrase: "TREZOR")
        let second = try Bip39.seed(mnemonic: vector.words, passphrase: "TREZOR")
        XCTAssertEqual(first, second)
    }

    func testSeedIsAlwaysSixtyFourBytes() throws {
        let file = try Self.loadVectors()
        let twelve = try Bip39.seed(mnemonic: file.vectors[0].words, passphrase: "TREZOR")
        let twentyFour = try Bip39.seed(
            mnemonic: file.vectors.last!.words, passphrase: "TREZOR")
        XCTAssertEqual(twelve.count, 64)
        XCTAssertEqual(twentyFour.count, 64)
    }

    // MARK: - Hex helpers (uniquely named — other test files carry their own)

    /// First `count` bytes as a lowercase hex string (cross-anchor assertions).
    private func hexPrefix(_ data: Data, _ count: Int) -> String {
        data.prefix(count).map { String(format: "%02x", $0) }.joined()
    }
}

private extension Data {
    /// Decodes an even-length hex string. Uniquely named initializer so it
    /// cannot collide with helpers in other test files.
    init(hexDecoded hex: String) {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}
