import XCTest
@testable import RavenCore

/// RECOV-01 (07-01 Task 1): the `[1-byte length][UTF-8]` framing that makes
/// the vault master passphrase a self-delimiting Shamir split input (D-01,
/// research §1). Framing, full-ceremony round-trip, rejection, and the
/// public vectors in Docs/TEST-VECTORS/shamir-passphrase-payload.json.
final class ShamirPassphrasePayloadTests: XCTestCase {

    private func expectDecodeError(_ data: Data, _ expected: ShamirPassphrasePayloadError) {
        XCTAssertThrowsError(try ShamirPassphrasePayload.decode(data)) { error in
            XCTAssertEqual(error as? ShamirPassphrasePayloadError, expected)
        }
    }

    // MARK: - Framing

    func testEncodeProducesLengthPrefixedUTF8() throws {
        // Pinned in the fixture JSON as payload_hex.
        let payload = try ShamirPassphrasePayload.encode(passphrase: "correct horse")
        XCTAssertEqual(payload, Data([0x0D]) + Data("correct horse".utf8))
    }

    func testEncodeRejectsEmptyAndOverlongPassphrases() {
        XCTAssertThrowsError(try ShamirPassphrasePayload.encode(passphrase: "")) { error in
            XCTAssertEqual(error as? ShamirPassphrasePayloadError, .empty)
        }

        // 255 one-byte characters = 255 UTF-8 bytes > the 254 ceiling → tooLong
        // (keeps the framed payload inside the paper format's 255-byte bound).
        let tooLong = String(repeating: "a", count: 255)
        XCTAssertThrowsError(try ShamirPassphrasePayload.encode(passphrase: tooLong)) { error in
            XCTAssertEqual(error as? ShamirPassphrasePayloadError, .tooLong)
        }

        // Boundary: exactly 254 bytes is legal.
        XCTAssertNoThrow(try ShamirPassphrasePayload.encode(passphrase: String(repeating: "a", count: 254)))
    }

    func testDecodeRejectsMalformedFraming() {
        expectDecodeError(Data(), .malformed)                       // empty payload
        expectDecodeError(Data([0x00, 0x61]), .malformed)           // length 0
        expectDecodeError(Data([0x02, 0x61]), .malformed)           // L=2 but 1 byte present
        expectDecodeError(Data([0x01, 0x61, 0x62]), .malformed)     // trailing garbage
    }

    func testDecodeRejectsNonRoundTrippingBytes() {
        // 0xFF is not a valid UTF-8 sequence — String(decoding:) replaces it
        // with U+FFFD, so the re-encode differs and decode must report
        // notRoundTripping instead of returning mojibake (research §1).
        expectDecodeError(Data([0x01, 0xFF]), .notRoundTripping)
    }

    func testRoundTripPreservesExactBytesNoNormalization() throws {
        // A precomposed-and-decomposed pair keeps distinct bytes: no NFC
        // anywhere. (Swift String == compares by canonical equivalence, so
        // distinctness is asserted on the UTF-8 bytes.)
        let precomposed = "caf\u{00E9}"
        let decomposed = "cafe\u{0301}"
        XCTAssertNotEqual(Data(precomposed.utf8), Data(decomposed.utf8))
        XCTAssertEqual([UInt8](precomposed.utf8), [0x63, 0x61, 0x66, 0xC3, 0xA9])
        XCTAssertEqual([UInt8](decomposed.utf8), [0x63, 0x61, 0x66, 0x65, 0xCC, 0x81])
        for variant in [precomposed, decomposed] {
            let bytes = [UInt8](variant.utf8)
            let payload = try ShamirPassphrasePayload.encode(passphrase: variant)
            XCTAssertEqual([UInt8](payload), [UInt8(bytes.count)] + bytes)
            XCTAssertEqual([UInt8](try ShamirPassphrasePayload.decode(payload).utf8), bytes)
        }

        // Multi-byte and symbol-heavy passphrases round-trip verbatim.
        for passphrase in ["correct horse battery staple", " passphrase with  spaces ", "pässwörd-🔐-2026", "x"] {
            let payload = try ShamirPassphrasePayload.encode(passphrase: passphrase)
            XCTAssertEqual(payload, Data([UInt8(passphrase.utf8.count)]) + Data(passphrase.utf8))
            XCTAssertEqual(try ShamirPassphrasePayload.decode(payload), passphrase)
        }
    }

    // MARK: - Full ceremony round-trip (encode → split → paper → recover → decode)

    func testFullCeremonyRoundTrip() throws {
        let passphrase = "correct horse battery staple"
        let payload = try ShamirPassphrasePayload.encode(passphrase: passphrase)
        let shares = try ShamirSecretSharing.split(secret: payload, threshold: 3, totalShares: 5)
        let papers = try shares.map { try ShamirPaperFormat.encode(share: $0, threshold: 3, totalShares: 5) }

        // All five paper strings print at identical width.
        XCTAssertEqual(Set(papers.map { $0.replacingOccurrences(of: "-", with: "").count }).count, 1)

        // Any 3 of the 5 rebuild the exact passphrase String.
        let indices: [[Int]] = [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]]
        for subset in indices {
            let recovered = try ShamirPassphrasePayload.decode(
                try ShamirPaperFormat.recover(fromPaper: subset.map { papers[$0] }))
            XCTAssertEqual(recovered, passphrase, "subset \(subset)")
        }
    }

    // MARK: - Public test vectors (Docs/TEST-VECTORS/shamir-passphrase-payload.json)

    static let vectorsURL = URL(fileURLWithPath: TestFixtures.repoRoot)
        .appendingPathComponent("Docs/TEST-VECTORS/shamir-passphrase-payload.json")

    private struct VectorFile: Decodable {
        struct Vector: Decodable {
            let name: String
            let passphrase: String
            let threshold: Int
            let total: Int
            let payload_hex: String
            let share_value_hex: [String]
            let paper: [String]
        }
        let format: String
        let version: Int
        let vectors: [Vector]
    }

    private func loadVectors() throws -> VectorFile {
        guard FileManager.default.fileExists(atPath: Self.vectorsURL.path) else {
            XCTFail("Missing \(Self.vectorsURL.path) — the public vectors must stay committed (PITFALL #12: single source of truth, no Swift literal copies)")
            throw NSError(domain: "ShamirPassphrasePayloadTests", code: 1)
        }
        return try JSONDecoder().decode(VectorFile.self, from: Data(contentsOf: Self.vectorsURL))
    }

    private func data(_ hex: String) -> Data {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return Data(bytes)
    }

    func testVectorsEnvelope() throws {
        let file = try loadVectors()
        XCTAssertEqual(file.format, "ravenvault-shamir-passphrase-payload")
        XCTAssertEqual(file.version, 1)
        for vector in file.vectors {
            XCTAssertEqual(vector.share_value_hex.count, vector.total, vector.name)
            XCTAssertEqual(vector.paper.count, vector.total, vector.name)
        }
    }

    func testVectorsPinFramingAndPaperStrings() throws {
        let file = try loadVectors()
        for vector in file.vectors {
            XCTAssertEqual(try ShamirPassphrasePayload.encode(passphrase: vector.passphrase), data(vector.payload_hex), vector.name)
            for (offset, hex) in vector.share_value_hex.enumerated() {
                let paper = try ShamirPaperFormat.encode(
                    share: ShamirShare(index: UInt8(offset + 1), value: data(hex)),
                    threshold: UInt8(vector.threshold),
                    totalShares: UInt8(vector.total))
                XCTAssertEqual(paper, vector.paper[offset], "\(vector.name) share \(offset + 1)")
            }
        }
    }

    func testVectorsRecoverPassphraseFromPaperSubsets() throws {
        let file = try loadVectors()
        for vector in file.vectors {
            let papers = vector.paper
            // First threshold shares + the last threshold shares (different
            // subsets must agree — the pinned values are consistent
            // evaluations of one polynomial).
            for subset in [Array(0..<vector.threshold), Array((vector.total - vector.threshold)..<vector.total)] {
                let recovered = try ShamirPassphrasePayload.decode(
                    try ShamirPaperFormat.recover(fromPaper: subset.map { papers[$0] }))
                XCTAssertEqual(recovered, vector.passphrase, "\(vector.name) subset \(subset)")
            }
        }
    }

    // MARK: - One-time vector generation

    /// Deterministic byte derivation (SHA-256 based), same discipline as
    /// shamir-paper-v1.json: the committed vectors are reproducible without
    /// hand-typed magic hex.
    private func deterministicBytes(label: String, count: Int) -> Data {
        var out = Data()
        var counter: UInt8 = 0
        while out.count < count {
            out.append(Hmac.sha256(Data("\(label)/\(counter)".utf8)))
            counter &+= 1
        }
        return out.prefix(count)
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// Horner evaluation of one byte's polynomial `[constant, c1, c2, …]`
    /// at `x` in GF(2^8) — the same scheme `ShamirSecretSharing.split` uses,
    /// with the constant term pinned to the payload byte so every threshold
    /// subset of the derived shares reconstructs the payload exactly.
    private func evaluate(coefficients: [UInt8], at x: UInt8) -> UInt8 {
        var result: UInt8 = 0
        for coefficient in coefficients.reversed() {
            result = ShamirSecretSharing.gfMultiply(result, x) ^ coefficient
        }
        return result
    }

    /// One-time regeneration of the public vectors. Ordinary `swift test`
    /// never rewrites the committed JSON:
    ///   GENERATE_VECTORS=1 swift test --filter testGeneratePassphrasePayloadVectors
    func testGeneratePassphrasePayloadVectors() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_VECTORS"] == "1" else {
            throw XCTSkip("Set GENERATE_VECTORS=1 to regenerate Docs/TEST-VECTORS/shamir-passphrase-payload.json")
        }

        let specs: [(name: String, passphrase: String, threshold: Int, total: Int)] = [
            ("3-of-5 passphrase 'correct horse' (primary recovery profile)", "correct horse", 3, 5),
            ("2-of-2 single-character passphrase (minimum-length boundary)", "x", 2, 2),
        ]

        struct Vector: Encodable {
            let name: String
            let passphrase: String
            let threshold: Int
            let total: Int
            let payload_hex: String
            let share_value_hex: [String]
            let paper: [String]
        }
        struct File: Encodable {
            let format = "ravenvault-shamir-passphrase-payload"
            let version = 1
            let vectors: [Vector]
        }

        var vectors: [Vector] = []
        for (file, spec) in specs.enumerated() {
            let payload = try ShamirPassphrasePayload.encode(passphrase: spec.passphrase)
            let valueLength = payload.count

            // Deterministic non-constant coefficients (degree threshold-1),
            // per payload byte — same shape split() draws at random, pinned
            // here so the committed vectors are reproducible.
            let higherCoefficients = (1..<spec.threshold).map { degree in
                deterministicBytes(label: "ravenvault-passphrase-payload-v1 coeff \(file)/\(degree)", count: valueLength)
            }
            var shareValues: [Data] = []
            for share in 1...spec.total {
                let value = Data((0..<valueLength).map { byte in
                    evaluate(
                        coefficients: [payload[byte + payload.startIndex]] + higherCoefficients.map { $0[byte + $0.startIndex] },
                        at: UInt8(share))
                })
                shareValues.append(value)
            }

            let papers = try shareValues.enumerated().map { offset, value in
                try ShamirPaperFormat.encode(
                    share: ShamirShare(index: UInt8(offset + 1), value: value),
                    threshold: UInt8(spec.threshold),
                    totalShares: UInt8(spec.total))
            }

            // Self-check before writing: paper-only recovery rebuilds the payload.
            XCTAssertEqual(
                try ShamirPaperFormat.recover(fromPaper: Array(papers.prefix(spec.threshold))),
                payload, spec.name)
            if spec.total > spec.threshold {
                let altSubset = Array(((spec.total - spec.threshold)..<spec.total).reversed())
                XCTAssertEqual(
                    try ShamirPaperFormat.recover(fromPaper: altSubset.map { papers[$0] }),
                    payload, spec.name)
            }

            vectors.append(Vector(
                name: spec.name,
                passphrase: spec.passphrase,
                threshold: spec.threshold,
                total: spec.total,
                payload_hex: hex(payload),
                share_value_hex: shareValues.map(hex),
                paper: papers))
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let json = try encoder.encode(File(vectors: vectors))
        try json.write(to: Self.vectorsURL, options: [.atomic])
    }
}
