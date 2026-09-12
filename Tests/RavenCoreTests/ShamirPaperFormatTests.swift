import XCTest
@testable import RavenCore

/// CORE-08: the Shamir share paper format — Crockford Base32 over the v1 wire
/// layout with a CRC-32/ISO-HDLC checksum verified BEFORE any header
/// interpretation or `combine` call (D-04/D-05, T-01-03).
final class ShamirPaperFormatTests: XCTestCase {

    private func randomBytes(_ count: Int) -> Data {
        SecureRandom.bytes(count: count)
    }

    private func makePaper(value: Data, index: UInt8, threshold: UInt8 = 3, total: UInt8 = 5) throws -> String {
        try ShamirPaperFormat.encode(share: ShamirShare(index: index, value: value), threshold: threshold, totalShares: total)
    }

    // MARK: - CRC-32/ISO-HDLC standard check value

    func testCRC32StandardCheckValue() {
        // The canonical check value of CRC-32/ISO-HDLC (IEEE): CRC of ASCII
        // "123456789" is 0xCBF43926. Guards the shared CRC32 used by the
        // paper format (and gzip).
        XCTAssertEqual(CRC32.checksum(Data("123456789".utf8)), 0xCBF4_3926)
    }

    // MARK: - Round trip

    func testEncodeDecodeRoundTripPreservesAllFields() throws {
        let value = randomBytes(32)
        for index: UInt8 in [1, 2, 3, 4, 5] {
            let paper = try makePaper(value: value, index: index)
            let decoded = try ShamirPaperFormat.decode(paper)
            XCTAssertEqual(decoded.share, ShamirShare(index: index, value: value))
            XCTAssertEqual(decoded.threshold, 3)
            XCTAssertEqual(decoded.totalShares, 5)
            XCTAssertEqual(decoded.version, ShamirPaperFormat.versionByte)
        }
    }

    func testEncodeIsDeterministic() throws {
        let value = randomBytes(32)
        let first = try makePaper(value: value, index: 2)
        let second = try makePaper(value: value, index: 2)
        XCTAssertEqual(first, second)
    }

    func testWhitespaceWrappedShareDecodesIdentically() throws {
        // Spec §3: cards may wrap lines every 4–5 groups; §5 step 1 is
        // normative — "strip separators/whitespace" before decoding. Lowercase,
        // hyphenated, and space-wrapped variants of one share must all decode
        // to the same thing.
        let paper = try makePaper(value: randomBytes(32), index: 2)
        let reference = try ShamirPaperFormat.decode(paper)
        XCTAssertEqual(try ShamirPaperFormat.decode(paper.lowercased()), reference, "lowercased share")

        // Print layout of §3: groups joined with spaces, line break every
        // 4 groups, trailing whitespace.
        let groups = paper.split(separator: "-").map(String.init)
        var wrapped = ""
        for (position, group) in groups.enumerated() {
            if position > 0, position % 4 == 0 { wrapped += "\n" }
            wrapped += group + " "
        }
        XCTAssertEqual(try ShamirPaperFormat.decode(wrapped), reference, "space/newline-wrapped share")

        // Whitespace standing in for the group separators is stripped too.
        XCTAssertEqual(
            try ShamirPaperFormat.decode(paper.replacingOccurrences(of: "-", with: " \t")),
            reference,
            "whitespace in place of hyphens"
        )
    }

    func testFixedWidthAndPresentationFor32ByteValue() throws {
        // B = 9 + 32 = 41 encoded bytes → width = ceil(8·41/5) = 66 characters.
        let paper = try makePaper(value: randomBytes(32), index: 1)
        let compact = paper.replacingOccurrences(of: "-", with: "")
        XCTAssertEqual(compact.count, 66, "L=32 must print at fixed width 66")

        let groups = paper.split(separator: "-")
        XCTAssertEqual(groups.count, 14, "66 chars = 13 groups of 5 + 1 short trailing group")
        for (position, group) in groups.enumerated() {
            if position < groups.count - 1 {
                XCTAssertEqual(group.count, 5, "interior groups must be exactly 5 characters")
            }
        }
        XCTAssertTrue(compact.allSatisfy { CrockfordBase32.alphabet.contains($0) }, "alphabet only")
    }

    func testBoundaryLengthOneValue() throws {
        let paper = try makePaper(value: Data([0x7B]), index: 1, threshold: 2, total: 2)
        let decoded = try ShamirPaperFormat.decode(paper)
        XCTAssertEqual(decoded.share.value, Data([0x7B]))
        XCTAssertEqual(decoded.threshold, 2)
        XCTAssertEqual(decoded.totalShares, 2)
        // B = 9 + 1 = 10 → width = ceil(80/5) = 16
        XCTAssertEqual(paper.replacingOccurrences(of: "-", with: "").count, 16)
    }

    // MARK: - Single-symbol corruption is always rejected (T-01-03)

    func testEverySingleSymbolCorruptionFailsChecksum() throws {
        let paper = try makePaper(value: randomBytes(32), index: 3)
        let compact = paper.replacingOccurrences(of: "-", with: "")
        let original = Array(compact)

        var rejected = 0
        for position in 0..<original.count {
            for substitute in CrockfordBase32.alphabet where substitute != original[position] {
                var corrupted = original
                corrupted[position] = substitute
                XCTAssertThrowsError(
                    try ShamirPaperFormat.decode(String(corrupted)),
                    "corruption at \(position) → \(substitute) must be rejected"
                ) { error in
                    if case ShamirPaperFormatError.checksumMismatch = error { rejected += 1 }
                }
            }
        }
        // 66 positions × 31 alternatives — every single-symbol mis-transcription.
        XCTAssertEqual(rejected, original.count * (CrockfordBase32.alphabet.count - 1))
    }

    // MARK: - Character validation

    func testCrockfordAliasesCaseInsensitivityAndRejections() throws {
        // I/L → 1, O → 0 (any case); case-insensitive throughout. Vector
        // pairs use canonical forms (final padding bits zero).
        XCTAssertEqual(try CrockfordBase32.decode("o4"), try CrockfordBase32.decode("04"))
        XCTAssertEqual(try CrockfordBase32.decode("I4"), try CrockfordBase32.decode("14"))
        XCTAssertEqual(try CrockfordBase32.decode("aBcDe"), try CrockfordBase32.decode("ABCDE"))

        // U is rejected in any case form (reserved for the mod-37 checksum
        // we do not use).
        for forbidden in ["U", "u"] {
            XCTAssertThrowsError(try CrockfordBase32.decode(forbidden)) { error in
                XCTAssertEqual(error as? ShamirPaperFormatError, .invalidCharacter)
            }
        }

        // Foreign symbol.
        XCTAssertThrowsError(try CrockfordBase32.decode("AAAA!BBBB")) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .invalidCharacter)
        }

        // Hyphens are ignored.
        XCTAssertEqual(try CrockfordBase32.decode("ABC-DE"), try CrockfordBase32.decode("ABCDE"))

        // End-to-end: a lowercased paper decodes to the same share.
        let paper = try makePaper(value: randomBytes(32), index: 2)
        let decoded = try ShamirPaperFormat.decode(paper.lowercased())
        let reference = try ShamirPaperFormat.decode(paper)
        XCTAssertEqual(decoded, reference)
    }

    func testNonCanonicalPaddingBitsRejected() throws {
        // The printed form is canonical: the final character's low padding
        // bits are always zero. A symbol that differs ONLY in those bits
        // decodes to the same bytes — it must still be rejected, so that
        // every single-symbol substitution of a paper string fails.
        let compact = try makePaper(value: randomBytes(32), index: 1).replacingOccurrences(of: "-", with: "")
        var characters = Array(compact)
        let lastIndex = CrockfordBase32.alphabet.firstIndex(of: characters[65])!
        XCTAssertEqual(lastIndex % 4, 0, "canonical final character has zero padding bits")
        let paddingOnlyVariant = CrockfordBase32.alphabet[lastIndex + 1] // same payload bits, padding = 01
        characters[65] = paddingOnlyVariant
        XCTAssertThrowsError(try ShamirPaperFormat.decode(String(characters))) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .checksumMismatch)
        }
    }

    // MARK: - Decode order: CRC precedes header interpretation

    /// Builds a paper string from raw wire bytes (test-side re-encode).
    private func paper(fromRawBytes raw: [UInt8]) -> String {
        var bytes = raw
        let crc = CRC32.checksum(Data(raw))
        bytes.append(UInt8((crc >> 24) & 0xFF))
        bytes.append(UInt8((crc >> 16) & 0xFF))
        bytes.append(UInt8((crc >> 8) & 0xFF))
        bytes.append(UInt8(crc & 0xFF))
        let width = (8 * bytes.count + 4) / 5
        return ShamirPaperFormat.present(CrockfordBase32.encode(Data(bytes), width: width))
    }

    func testVersionTwoIsRejectedAsUnsupported() throws {
        let raw: [UInt8] = [0x02, 3, 5, 1, 4, 0xAA, 0xBB, 0xCC, 0xDD]
        XCTAssertThrowsError(try ShamirPaperFormat.decode(paper(fromRawBytes: raw))) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .versionUnsupported(0x02))
        }
    }

    func testChecksumFailurePrecedesVersionInterpretation() throws {
        // A v2 header with a corrupt checksum must fail as checksumMismatch —
        // never as versionUnsupported (CRC verify comes first, T-01-03).
        var raw: [UInt8] = [0x02, 3, 5, 1, 4, 0xAA, 0xBB, 0xCC, 0xDD]
        var bytes = raw
        let crc = CRC32.checksum(Data(bytes))
        bytes.append(UInt8((crc >> 24) & 0xFF))
        bytes.append(UInt8((crc >> 16) & 0xFF))
        bytes.append(UInt8((crc >> 8) & 0xFF))
        bytes.append(UInt8(crc & 0xFF))
        bytes[bytes.count - 1] ^= 0xFF // corrupt stored checksum
        let width = (8 * bytes.count + 4) / 5
        let corrupt = ShamirPaperFormat.present(CrockfordBase32.encode(Data(bytes), width: width))
        XCTAssertThrowsError(try ShamirPaperFormat.decode(corrupt)) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .checksumMismatch)
        }
        _ = raw // (v2 payload documented above)
    }

    func testEmptyAndTruncatedInputsAreUnexpectedEnd() {
        XCTAssertThrowsError(try ShamirPaperFormat.decode("")) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .unexpectedEnd)
        }
        XCTAssertThrowsError(try ShamirPaperFormat.decode("---")) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .unexpectedEnd)
        }
        XCTAssertThrowsError(try ShamirPaperFormat.decode("AAAAA")) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .unexpectedEnd)
        }
    }

    // MARK: - Encode parameter guards

    func testInvalidConfigurationRejected() throws {
        let value = randomBytes(8)
        XCTAssertThrowsError(try makePaper(value: value, index: 1, threshold: 1, total: 3)) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try makePaper(value: value, index: 1, threshold: 4, total: 3)) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try makePaper(value: value, index: 0, threshold: 2, total: 3)) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try makePaper(value: Data(), index: 1, threshold: 2, total: 3)) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try makePaper(value: randomBytes(256), index: 1, threshold: 2, total: 3)) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .invalidConfiguration)
        }
    }

    // MARK: - Paper-only recovery

    func testRecoverFromEveryThreeOfFivePaperCombination() throws {
        let secret = randomBytes(32)
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 3, totalShares: 5)
        let papers = try shares.map { try ShamirPaperFormat.encode(share: $0, threshold: 3, totalShares: 5) }

        for first in 0..<5 {
            for second in (first + 1)..<5 {
                for third in (second + 1)..<5 {
                    let recovered = try ShamirPaperFormat.recover(
                        fromPaper: [papers[first], papers[second], papers[third]]
                    )
                    XCTAssertEqual(recovered, secret, "subset \(first),\(second),\(third) failed")
                }
            }
        }
    }

    func testRecoverTwoOfThree() throws {
        let secret = randomBytes(16)
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 2, totalShares: 3)
        let papers = try shares.map { try ShamirPaperFormat.encode(share: $0, threshold: 2, totalShares: 3) }
        XCTAssertEqual(try ShamirPaperFormat.recover(fromPaper: [papers[0], papers[2]]), secret)
    }

    func testRecoverRejectsDuplicatesInsufficiencyAndMixedHeaders() throws {
        let shares3of5 = try ShamirSecretSharing.split(secret: randomBytes(32), threshold: 3, totalShares: 5)
        let papers3of5 = try shares3of5.map { try ShamirPaperFormat.encode(share: $0, threshold: 3, totalShares: 5) }

        // Duplicate index (same share twice).
        XCTAssertThrowsError(try ShamirPaperFormat.recover(fromPaper: [papers3of5[0], papers3of5[0]])) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .duplicateShareIndex)
        }

        // Below threshold.
        XCTAssertThrowsError(try ShamirPaperFormat.recover(fromPaper: [papers3of5[1], papers3of5[3]])) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .insufficientShares)
        }

        // Empty input.
        XCTAssertThrowsError(try ShamirPaperFormat.recover(fromPaper: [])) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .insufficientShares)
        }

        // Mixed headers (3-of-5 share + 2-of-3 share).
        let shares2of3 = try ShamirSecretSharing.split(secret: randomBytes(32), threshold: 2, totalShares: 3)
        let paper2of3 = try ShamirPaperFormat.encode(share: shares2of3[0], threshold: 2, totalShares: 3)
        XCTAssertThrowsError(try ShamirPaperFormat.recover(fromPaper: [papers3of5[0], paper2of3])) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .inconsistentHeaders)
        }
    }

    func testRecoverRejectsCorruptedPaperBeforeCombining() throws {
        // A corrupted share must surface as its own typed decode error
        // (checksumMismatch), never flow into combine.
        let shares = try ShamirSecretSharing.split(secret: randomBytes(32), threshold: 2, totalShares: 3)
        var papers = try shares.map { try ShamirPaperFormat.encode(share: $0, threshold: 2, totalShares: 3) }

        var compact = Array(papers[0].replacingOccurrences(of: "-", with: ""))
        compact[0] = compact[0] == "0" ? "1" : "0" // deterministic single-symbol corruption
        papers[0] = ShamirPaperFormat.present(String(compact))

        XCTAssertThrowsError(try ShamirPaperFormat.recover(fromPaper: papers)) { error in
            XCTAssertEqual(error as? ShamirPaperFormatError, .checksumMismatch)
        }
    }

    // MARK: - Public test vectors (Docs/TEST-VECTORS/shamir-paper-v1.json)

    static let vectorsURL = URL(fileURLWithPath: TestFixtures.repoRoot)
        .appendingPathComponent("Docs/TEST-VECTORS/shamir-paper-v1.json")

    private struct VectorFile: Decodable {
        struct Vector: Decodable {
            let name: String
            let threshold: Int
            let total: Int
            let secret_hex: String
            let share_value_hex: [String]
            let paper: [String]
        }
        let format: String
        let version: Int
        let encoding: String
        let checksum: String
        let vectors: [Vector]
    }

    private func loadVectors() throws -> VectorFile {
        guard FileManager.default.fileExists(atPath: Self.vectorsURL.path) else {
            XCTFail("Missing \(Self.vectorsURL.path) — the public vectors must stay committed (PITFALL #12: single source of truth, no Swift literal copies)")
            throw NSError(domain: "ShamirPaperFormatTests", code: 1)
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
        XCTAssertEqual(file.format, "ravenvault-shamir-paper")
        XCTAssertEqual(file.version, 1)
        XCTAssertEqual(file.encoding, "crockford-base32")
        XCTAssertEqual(file.checksum, "crc-32/iso-hdlc")
        XCTAssertGreaterThanOrEqual(file.vectors.count, 3)
        for vector in file.vectors {
            XCTAssertEqual(vector.share_value_hex.count, vector.total, vector.name)
            XCTAssertEqual(vector.paper.count, vector.total, vector.name)
        }
    }

    func testVectorsEncodeProducesPinnedPaper() throws {
        let file = try loadVectors()
        for vector in file.vectors {
            for (offset, hex) in vector.share_value_hex.enumerated() {
                let paper = try ShamirPaperFormat.encode(
                    share: ShamirShare(index: UInt8(offset + 1), value: data(hex)),
                    threshold: UInt8(vector.threshold),
                    totalShares: UInt8(vector.total)
                )
                XCTAssertEqual(paper, vector.paper[offset], "\(vector.name) share \(offset + 1)")
            }
        }
    }

    func testVectorsDecodeReturnsPinnedShare() throws {
        let file = try loadVectors()
        for vector in file.vectors {
            for (offset, paper) in vector.paper.enumerated() {
                let decoded = try ShamirPaperFormat.decode(paper)
                XCTAssertEqual(decoded.share.index, UInt8(offset + 1), vector.name)
                XCTAssertEqual(decoded.share.value, data(vector.share_value_hex[offset]), vector.name)
                XCTAssertEqual(decoded.threshold, UInt8(vector.threshold), vector.name)
                XCTAssertEqual(decoded.totalShares, UInt8(vector.total), vector.name)
                XCTAssertEqual(decoded.version, 1, vector.name)
            }
        }
    }

    func testVectorsPaperOnlyRecoveryFromEveryCombination() throws {
        let file = try loadVectors()
        for vector in file.vectors {
            let secret = data(vector.secret_hex)
            let papers = vector.paper

            func assertRecovers(_ indices: [Int], _ label: String) throws {
                let subset = indices.map { papers[$0] }
                XCTAssertEqual(try ShamirPaperFormat.recover(fromPaper: subset), secret, "\(vector.name) subset \(label)")
            }

            switch vector.threshold {
            case 2:
                for first in 0..<papers.count {
                    for second in (first + 1)..<papers.count {
                        try assertRecovers([first, second], "\(first),\(second)")
                    }
                }
            default:
                for first in 0..<papers.count {
                    for second in (first + 1)..<papers.count {
                        for third in (second + 1)..<papers.count {
                            try assertRecovers([first, second, third], "\(first),\(second),\(third)")
                        }
                    }
                }
            }
        }
    }

    func testVectorsRejectEverySingleSymbolCorruption() throws {
        let file = try loadVectors()
        for vector in file.vectors {
            for paper in vector.paper {
                let compact = Array(paper.replacingOccurrences(of: "-", with: ""))
                for position in 0..<compact.count {
                    for substitute in CrockfordBase32.alphabet where substitute != compact[position] {
                        var corrupted = compact
                        corrupted[position] = substitute
                        XCTAssertThrowsError(try ShamirPaperFormat.decode(String(corrupted))) { error in
                            XCTAssertEqual(
                                error as? ShamirPaperFormatError,
                                .checksumMismatch,
                                "\(vector.name): corruption at \(position) → \(substitute)"
                            )
                        }
                    }
                }
            }
        }
    }

    // MARK: - One-time vector generation

    /// Deterministic byte derivation (SHA-256 based) so the committed vectors
    /// are reproducible without hand-typed magic hex.
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

    /// Lagrange evaluation at `x` of the polynomial through `points` in
    /// GF(2^8) (subtraction is XOR). Uses the engine's own field arithmetic —
    /// the paper format's pinned shares must be *consistent* evaluations of
    /// one polynomial, otherwise different subsets reconstruct different
    /// secrets.
    private func interpolate(at x: UInt8, points: [(index: UInt8, value: UInt8)]) -> UInt8 {
        var result: UInt8 = 0
        for j in 0..<points.count {
            let xj = points[j].index
            let yj = points[j].value
            var numerator: UInt8 = 1
            var denominator: UInt8 = 1
            for m in 0..<points.count where m != j {
                let xm = points[m].index
                numerator = ShamirSecretSharing.gfMultiply(numerator, x ^ xm)
                denominator = ShamirSecretSharing.gfMultiply(denominator, xj ^ xm)
            }
            result ^= ShamirSecretSharing.gfMultiply(yj, ShamirSecretSharing.gfDivide(numerator, denominator))
        }
        return result
    }

    /// One-time regeneration of the public vectors. Ordinary `swift test`
    /// never rewrites the committed JSON:
    ///   GENERATE_VECTORS=1 swift test --filter testGenerateShamirPaperVectors
    func testGenerateShamirPaperVectors() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_VECTORS"] == "1" else {
            throw XCTSkip("Set GENERATE_VECTORS=1 to regenerate Docs/TEST-VECTORS/shamir-paper-v1.json")
        }

        let specs: [(name: String, threshold: Int, total: Int, valueLength: Int)] = [
            ("3-of-5 with a 32-byte secret (primary recovery profile)", 3, 5, 32),
            ("2-of-3 with a 16-byte secret", 2, 3, 16),
            ("2-of-2 with a 1-byte secret (minimum-length boundary)", 2, 2, 1),
        ]

        struct Vector: Encodable {
            let name: String
            let threshold: Int
            let total: Int
            let secret_hex: String
            let share_value_hex: [String]
            let paper: [String]
        }
        struct File: Encodable {
            let format = "ravenvault-shamir-paper"
            let version = 1
            let encoding = "crockford-base32"
            let checksum = "crc-32/iso-hdlc"
            let vectors: [Vector]
        }

        var vectors: [Vector] = []
        for (file, spec) in specs.enumerated() {
            // Pin the first `threshold` share values deterministically, derive
            // the secret as their reconstruction constant, and compute the
            // remaining shares by polynomial interpolation so that EVERY
            // threshold-subset recovers the same secret.
            let pinnedShares = (1...spec.threshold).map { share -> ShamirShare in
                ShamirShare(
                    index: UInt8(share),
                    value: deterministicBytes(label: "ravenvault-shamir-paper-v1 share \(file)/\(share)", count: spec.valueLength)
                )
            }
            let secret = try ShamirSecretSharing.combine(shares: pinnedShares, threshold: spec.threshold)

            var shareValues = pinnedShares.map(\.value)
            if spec.total > spec.threshold {
                for index in (spec.threshold + 1)...spec.total {
                    let value = Data((0..<spec.valueLength).map { byte in
                        interpolate(
                            at: UInt8(index),
                            points: pinnedShares.map { (index: $0.index, value: $0.value[byte]) }
                        )
                    })
                    shareValues.append(value)
                }
            }

            let papers = try shareValues.enumerated().map { offset, value in
                try ShamirPaperFormat.encode(
                    share: ShamirShare(index: UInt8(offset + 1), value: value),
                    threshold: UInt8(spec.threshold),
                    totalShares: UInt8(spec.total)
                )
            }
            // Self-check before writing: multiple subsets must recover.
            XCTAssertEqual(
                try ShamirPaperFormat.recover(fromPaper: Array(papers.prefix(spec.threshold))),
                secret, spec.name
            )
            if spec.total > spec.threshold {
                let altSubset = Array(((spec.total - spec.threshold)..<spec.total).reversed())
                XCTAssertEqual(
                    try ShamirPaperFormat.recover(fromPaper: altSubset.map { papers[$0] }),
                    secret, spec.name
                )
            }

            vectors.append(Vector(
                name: spec.name,
                threshold: spec.threshold,
                total: spec.total,
                secret_hex: hex(secret),
                share_value_hex: shareValues.map(hex),
                paper: papers
            ))
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        var json = try encoder.encode(File(vectors: vectors))
        json.append(0x0A) // trailing newline

        let dir = Self.vectorsURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try json.write(to: Self.vectorsURL)
        print("VECTORS-WRITTEN:", Self.vectorsURL.path)
    }
}
