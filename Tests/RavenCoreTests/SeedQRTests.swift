import XCTest
@testable import RavenCore

/// SeedQR Standard/Compact codecs against the public vectors (PITFALL #12:
/// single source of truth in Docs/TEST-VECTORS/, no Swift literal copies).
final class SeedQRTests: XCTestCase {

    struct VectorFile: Decodable {
        struct Vector: Decodable {
            let name: String
            let word_count: Int
            let mnemonic: [String]
            let standard_digits: String
            let compact_hex: String
        }
        let format: String
        let version: Int
        let vectors: [Vector]
    }

    static let vectorsURL = URL(fileURLWithPath: TestFixtures.repoRoot)
        .appendingPathComponent("Docs/TEST-VECTORS/seedqr-vectors.json")

    static func loadVectors() throws -> VectorFile {
        guard FileManager.default.fileExists(atPath: vectorsURL.path) else {
            XCTFail("Missing \(vectorsURL.path) — the public SeedQR vectors must stay committed")
            throw NSError(domain: "SeedQRTests", code: 1)
        }
        return try JSONDecoder().decode(VectorFile.self, from: Data(contentsOf: vectorsURL))
    }

    // MARK: - Envelope

    func testVectorsEnvelope() throws {
        let file = try Self.loadVectors()
        XCTAssertEqual(file.format, "ravenvault-seedqr")
        XCTAssertEqual(file.version, 1)
        XCTAssertGreaterThanOrEqual(file.vectors.count, 3)
        XCTAssertTrue(file.vectors.contains { $0.name == "seedsigner-readme-example" })
    }

    // MARK: - Five-direction assertions per vector

    func testPerVectorFiveDirections() throws {
        let file = try Self.loadVectors()
        for vector in file.vectors {
            let compact = try Data(hexVector: vector.compact_hex)

            // 1. standardEncode == standard_digits
            XCTAssertEqual(try SeedQR.standardEncode(vector.mnemonic),
                           vector.standard_digits, vector.name)
            // 2. standardDecode(standard_digits) == mnemonic
            XCTAssertEqual(try SeedQR.standardDecode(vector.standard_digits),
                           vector.mnemonic, vector.name)
            // 3. compactEncode == compact_hex bytes
            XCTAssertEqual(try SeedQR.compactEncode(vector.mnemonic), compact, vector.name)
            // 4. compactDecode(compact) == mnemonic
            XCTAssertEqual(try SeedQR.compactDecode(compact),
                           vector.mnemonic, vector.name)
            // 5. cross: standard-decoded words compact-encode to the same bytes
            let wordsFromStandard = try SeedQR.standardDecode(vector.standard_digits)
            XCTAssertEqual(try SeedQR.compactEncode(wordsFromStandard), compact, vector.name)
        }
    }

    func testCompactPayloadIsRawEntropy() throws {
        // Official Compact semantics (D-09 correction): the payload equals the
        // BIP39 entropy byte for byte — no 2-character word table.
        let file = try Self.loadVectors()
        for vector in file.vectors {
            XCTAssertEqual(try SeedQR.compactEncode(vector.mnemonic),
                           try Bip39.entropy(fromMnemonic: vector.mnemonic), vector.name)
            XCTAssertEqual(try SeedQR.compactEncode(vector.mnemonic),
                           try Data(hexVector: vector.compact_hex), vector.name)
        }
    }

    func testSeedsignerReadmeExampleAnchored() throws {
        // Cross-implementation anchor: the worked example from the SeedSigner
        // README. Its digits string is pinned in the public JSON; every codec
        // direction must reproduce it.
        let file = try Self.loadVectors()
        let example = try XCTUnwrap(file.vectors.first { $0.name == "seedsigner-readme-example" })
        XCTAssertEqual(example.word_count, 12)
        XCTAssertEqual(example.standard_digits.count, 48)

        let words = try SeedQR.standardDecode(example.standard_digits)
        XCTAssertEqual(words, example.mnemonic)
        XCTAssertEqual(try SeedQR.standardEncode(words), example.standard_digits)
        XCTAssertEqual(try SeedQR.compactEncode(words), try Data(hexVector: example.compact_hex))
        XCTAssertEqual(try SeedQR.compactDecode(try Data(hexVector: example.compact_hex)),
                       example.mnemonic)
    }

    // MARK: - Output sizes

    func testOutputSizes() throws {
        let file = try Self.loadVectors()
        let twelve = try XCTUnwrap(file.vectors.first { $0.word_count == 12 })
        let twentyFour = try XCTUnwrap(file.vectors.first { $0.word_count == 24 })

        XCTAssertEqual(try SeedQR.standardEncode(twelve.mnemonic).count, 48)
        XCTAssertEqual(try SeedQR.standardEncode(twentyFour.mnemonic).count, 96)
        XCTAssertEqual(try SeedQR.compactEncode(twelve.mnemonic).count, 16)
        XCTAssertEqual(try SeedQR.compactEncode(twentyFour.mnemonic).count, 32)
    }

    // MARK: - Negatives (typed errors, exact case)

    func testStandardWrongLengthRejected() throws {
        let vector = try Self.loadVectors().vectors[0]
        XCTAssertThrowsError(try SeedQR.standardDecode(String(vector.standard_digits.dropLast()))) { error in
            XCTAssertEqual(error as? SeedQRError, .invalidLength)
        }
        XCTAssertThrowsError(try SeedQR.standardDecode(vector.standard_digits + "0")) { error in
            XCTAssertEqual(error as? SeedQRError, .invalidLength)
        }
        XCTAssertThrowsError(try SeedQR.standardDecode("")) { error in
            XCTAssertEqual(error as? SeedQRError, .invalidLength)
        }
    }

    func testStandardIndexOutOfRangeRejected() throws {
        let vector = try Self.loadVectors().vectors[0]
        // 48 digits, but the first slice (9999) exceeds the 2047 index bound.
        let corrupted = "9999" + vector.standard_digits.dropFirst(4)
        XCTAssertEqual(corrupted.count, 48)
        XCTAssertThrowsError(try SeedQR.standardDecode(String(corrupted))) { error in
            XCTAssertEqual(error as? SeedQRError, .indexOutOfRange)
        }
    }

    func testStandardNonDigitRejected() throws {
        let vector = try Self.loadVectors().vectors[0]
        let corrupted = "00o0" + vector.standard_digits.dropFirst(4)
        XCTAssertThrowsError(try SeedQR.standardDecode(String(corrupted))) { error in
            XCTAssertEqual(error as? SeedQRError, .invalidDigit)
        }
    }

    func testStandardCorruptChecksumWordFailsChecksum() throws {
        // Corrupt bit 0 of the checksum word's index: ENT is unchanged so the
        // recomputed checksum stays fixed, while the received checksum now
        // differs — decode must fail the BIP39 gate deterministically.
        let vector = try Self.loadVectors().vectors[0]
        let digits = vector.standard_digits
        let lastIndex = try XCTUnwrap(Int(digits.suffix(4)))
        let corrupted = digits.prefix(digits.count - 4)
            + String(format: "%04d", lastIndex ^ 1)
        XCTAssertThrowsError(try SeedQR.standardDecode(String(corrupted))) { error in
            XCTAssertEqual(error as? Bip39Error, .invalidChecksum)
        }
    }

    func testCompactWrongPayloadLengthRejected() throws {
        let file = try Self.loadVectors()
        let twelve = try XCTUnwrap(file.vectors.first { $0.word_count == 12 })
        let twentyFour = try XCTUnwrap(file.vectors.first { $0.word_count == 24 })

        let compact12 = try Data(hexVector: twelve.compact_hex)
        let compact24 = try Data(hexVector: twentyFour.compact_hex)

        XCTAssertThrowsError(try SeedQR.compactDecode(compact12.dropLast())) { error in
            XCTAssertEqual(error as? SeedQRError, .invalidPayloadLength)
        }
        XCTAssertThrowsError(try SeedQR.compactDecode(compact24.dropLast())) { error in
            XCTAssertEqual(error as? SeedQRError, .invalidPayloadLength)
        }
        XCTAssertThrowsError(try SeedQR.compactDecode(compact12 + Data([0x00]))) { error in
            XCTAssertEqual(error as? SeedQRError, .invalidPayloadLength)
        }
        XCTAssertThrowsError(try SeedQR.compactDecode(Data())) { error in
            XCTAssertEqual(error as? SeedQRError, .invalidPayloadLength)
        }
    }

    func testCompactWellFormedPayloadAlwaysDecodes() throws {
        // BIP39 semantics: every 16/32-byte payload IS a valid entropy — the
        // checksum is regenerated, not verified, on this path (official
        // Compact behavior). Tampering yields a *different valid* mnemonic;
        // the length gate is compactDecode's only rejection.
        let vector = try Self.loadVectors().vectors[0]
        var tampered = try Data(hexVector: vector.compact_hex)
        tampered[0] ^= 0xFF

        let words = try SeedQR.compactDecode(tampered)
        XCTAssertEqual(words.count, 12)
        XCTAssertNotEqual(try SeedQR.compactEncode(words),
                          try Data(hexVector: vector.compact_hex))
        // The tampered phrase still round-trips (it is a valid mnemonic).
        XCTAssertEqual(try SeedQR.compactDecode(try SeedQR.compactEncode(words)), words)
    }

    func testStandardEncodeRejectsInvalidMnemonic() {
        XCTAssertThrowsError(try SeedQR.standardEncode(["abandon", "abandon"])) { error in
            XCTAssertEqual(error as? Bip39Error, .invalidWordCount)
        }
    }
}

private extension Data {
    /// Decodes an even-length hex string (each test file carries its own
    /// private hex helper — matching the existing suite convention).
    init(hexVector hex: String) {
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
