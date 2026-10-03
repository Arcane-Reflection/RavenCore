import CryptoKit
import XCTest
@testable import RavenCore

/// RECOV-03 (07-03 Task 1): the Secure Mirror container codec (D-06).
/// Fixture round-trip against the frozen public vectors, the full tamper
/// matrix, wrong-passphrase fail-closed, and the KDF-constant pin (a
/// parameter change breaks THIS suite, not users' mirrors — R7).
final class MirrorContainerTests: XCTestCase {

    /// Set GENERATE_VECTORS=1 to regenerate the canonical hex into
    /// Docs/TEST-VECTORS/mirror-v1.json (one-time discipline; the frozen
    /// values are a published contract — regeneration is for recovery from
    /// a codec bug ONLY, never routine).
    private static let generateVectors = ProcessInfo.processInfo.environment["GENERATE_VECTORS"] == "1"

    private static let fixturePassphrase = "mirror fixture passphrase"
    private static let fixtureSalt = Data([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ])
    private static let fixtureKdbx = Data("fake kdbx channel bytes".utf8)
    private static let fixtureNative = Data("fake ravenvault channel bytes, longer".utf8)

    private static func fixtureContainer() throws -> Data {
        try MirrorContainer.encrypt(
            payloads: [.kdbx: fixtureKdbx, .ravenvault: fixtureNative],
            passphrase: fixturePassphrase,
            salt: fixtureSalt)
    }

    private func loadVectors() throws -> [String: Any] {
        let url = URL(fileURLWithPath: TestFixtures.repoRoot)
            .appendingPathComponent("Docs/TEST-VECTORS/mirror-v1.json")
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func canonicalPrefixHex() throws -> (hex: String, payloadLength: UInt64) {
        let vectors = try loadVectors()
        let list = try XCTUnwrap(vectors["vectors"] as? [[String: Any]])
        let canonical = try XCTUnwrap(list.first { ($0["name"] as? String)?.contains("canonical") == true })
        return (
            try XCTUnwrap(canonical["container_prefix_hex"] as? String),
            UInt64(try XCTUnwrap(canonical["expected_payload_length"] as? Int))
        )
    }

    private func expectDecryptError(_ container: Data, _ expected: MirrorError,
                                     passphrase: String = "mirror fixture passphrase",
                                     line: UInt = #line) {
        XCTAssertThrowsError(
            try MirrorContainer.decrypt(container, passphrase: passphrase),
            line: line
        ) { error in
            XCTAssertEqual(error as? MirrorError, expected, line: line)
        }
    }

    // MARK: - Fixture round-trip

    func testCanonicalVectorMatchesByteForByte() throws {
        // The seal path draws a fresh random nonce per export (security
        // property — no deterministic nonce injection exists), so the
        // vector pins the DETERMINISTIC prefix (bytes 0..<37) plus the
        // payload length; the round-trip tests pin the rest.
        let container = try Self.fixtureContainer()
        let canonical = try canonicalPrefixHex()
        XCTAssertEqual(String(container.hexString.prefix(74)), canonical.hex)
        let info = try MirrorContainer.header(of: container)
        XCTAssertEqual(info.payloadLength, canonical.payloadLength)
    }

    func testRoundTripPreservesBothChannelsByteIdentically() throws {
        let decoded = try MirrorContainer.decrypt(try Self.fixtureContainer(), passphrase: Self.fixturePassphrase)
        XCTAssertEqual(decoded[.kdbx], Self.fixtureKdbx)
        XCTAssertEqual(decoded[.ravenvault], Self.fixtureNative)
        XCTAssertEqual(decoded.count, 2)
    }

    func testSingleChannelContainerDecodes() throws {
        let container = try MirrorContainer.encrypt(
            payloads: [.kdbx: Self.fixtureKdbx],
            passphrase: Self.fixturePassphrase, salt: Self.fixtureSalt)
        let decoded = try MirrorContainer.decrypt(container, passphrase: Self.fixturePassphrase)
        XCTAssertEqual(decoded[.kdbx], Self.fixtureKdbx)
        XCTAssertNil(decoded[.ravenvault])
    }

    // MARK: - Tamper matrix (T-07-03-01)

    func testFlippedMagicFailsClosed() throws {
        var container = try Self.fixtureContainer()
        container[0] ^= 0xFF
        expectDecryptError(container, .magicMismatch)
    }

    func testFutureVersionFailsClosed() throws {
        var container = try Self.fixtureContainer()
        container[4] = 0x00
        container[5] = 0x02 // version 2
        expectDecryptError(container, .versionUnsupported(2))
    }

    func testUnsupportedKDFIDFailsClosed() throws {
        var container = try Self.fixtureContainer()
        container[6] = 0x02
        expectDecryptError(container, .kdfUnsupported(2))
    }

    /// Hostile-header ceilings (261003-mk7 second pass): memory and
    /// parallelism claims above `KeyDerivation.hostileMax*` fail typed at the
    /// header boundary — before any Argon2 work and before the GCM check that
    /// used to be the only guard.
    func testHostileKDFParametersFailClosedAtHeader() throws {
        var hugeMemory = try Self.fixtureContainer()
        // Header layout: magic(0-3) version(4-5) kdf(6) memoryKiB BE(7-10)
        // timeCost(11) parallelism(12). 1.5 GiB in KiB = 0x00180000.
        hugeMemory[7] = 0x00
        hugeMemory[8] = 0x18
        hugeMemory[9] = 0x00
        hugeMemory[10] = 0x00
        expectDecryptError(hugeMemory, .kdfParametersUnsupported)

        var manyThreads = try Self.fixtureContainer()
        manyThreads[12] = 17
        expectDecryptError(manyThreads, .kdfParametersUnsupported)
    }

    func testTruncatedBodyFailsClosed() throws {
        var container = try Self.fixtureContainer()
        container = container.dropLast(5)
        expectDecryptError(container, .malformed)
    }

    func testUndersizedHeaderFailsClosed() {
        expectDecryptError(Data(repeating: 0x41, count: 10), .malformed)
    }

    func testFlippedCiphertextBitFailsClosedAsAuthentication() throws {
        var container = try Self.fixtureContainer()
        container[container.count - 1] ^= 0x01
        expectDecryptError(container, .authenticationFailed)
    }

    func testFlippedGCMTagBitFailsClosedAsAuthentication() throws {
        var container = try Self.fixtureContainer()
        container[container.count - 16] ^= 0x80
        expectDecryptError(container, .authenticationFailed)
    }

    func testWrongPassphraseYieldsAuthenticationFailed() throws {
        expectDecryptError(try Self.fixtureContainer(), .authenticationFailed,
                           passphrase: "not the fixture passphrase")
    }

    // MARK: - Payload framing

    func testUnknownBlobIDFailsClosed() throws {
        // Build a structurally valid container around a payload with an
        // unknown channel id (0x7F) — the tag must verify FIRST, then the
        // framing rejects the unknown id.
        let salt = Self.fixtureSalt
        let key = try KeyDerivation.argon2id(
            password: Data(Self.fixturePassphrase.utf8), salt: salt,
            memoryKiB: KeyDerivation.argon2MemoryKiB,
            timeCost: KeyDerivation.argon2TimeCost,
            parallelism: KeyDerivation.argon2Parallelism)
        let payload = Data([0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63])
        let sealed = try AESGCMCipher.encrypt(payload, key: SymmetricKey(data: key))
        var container = MirrorContainer.magic
        container.append(contentsOf: [0x00, 0x01, MirrorContainer.kdfID])
        container.append(Data([0x00, 0x01, 0x00, 0x00])) // 65536 BE
        container.append(UInt8(KeyDerivation.argon2TimeCost))
        container.append(UInt8(KeyDerivation.argon2Parallelism))
        container.append(salt)
        var len = Data()
        var c = UInt64(sealed.ciphertext.count)
        for _ in 0..<8 { len.append(UInt8(c & 0xFF)); c >>= 8 }
        container.append(Data(len.reversed()))
        container.append(sealed.nonce)
        container.append(sealed.ciphertext)
        expectDecryptError(container, .channelUnknown(0x7F))
    }

    func testBlobLengthOverrunFailsClosedAsMalformed() throws {
        // Valid container, then patch the inner blob length to overrun its
        // actual bytes — requires re-sealing, so rebuild via the same
        // construction as the unknown-id test but with a lying length.
        let salt = Self.fixtureSalt
        let key = try KeyDerivation.argon2id(
            password: Data(Self.fixturePassphrase.utf8), salt: salt,
            memoryKiB: KeyDerivation.argon2MemoryKiB,
            timeCost: KeyDerivation.argon2TimeCost,
            parallelism: KeyDerivation.argon2Parallelism)
        // kdbx blob claiming 0xFF bytes while carrying 3.
        var payload = Data([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x61, 0x62, 0x63])
        payload.append(Data("rest of payload".utf8))
        let sealed = try AESGCMCipher.encrypt(payload, key: SymmetricKey(data: key))
        var container = MirrorContainer.magic
        container.append(contentsOf: [0x00, 0x01, MirrorContainer.kdfID])
        container.append(Data([0x00, 0x01, 0x00, 0x00]))
        container.append(UInt8(KeyDerivation.argon2TimeCost))
        container.append(UInt8(KeyDerivation.argon2Parallelism))
        container.append(salt)
        var len = Data()
        var c = UInt64(sealed.ciphertext.count)
        for _ in 0..<8 { len.append(UInt8(c & 0xFF)); c >>= 8 }
        container.append(Data(len.reversed()))
        container.append(sealed.nonce)
        container.append(sealed.ciphertext)
        expectDecryptError(container, .malformed)
    }

    // MARK: - KDF constant pinning (R7)

    func testHeaderEchoesPinnedEngineConstants() throws {
        let info = try MirrorContainer.header(of: try Self.fixtureContainer())
        XCTAssertEqual(Int(info.memoryKiB), KeyDerivation.argon2MemoryKiB)
        XCTAssertEqual(Int(info.timeCost), KeyDerivation.argon2TimeCost)
        XCTAssertEqual(Int(info.parallelism), KeyDerivation.argon2Parallelism)
        XCTAssertEqual(info.version, 1)
        XCTAssertEqual(info.kdfID, 0x01)
        XCTAssertEqual(info.salt, Self.fixtureSalt)
    }

    func testEncryptRejectsBadSaltAndEmptyPassphrase() {
        XCTAssertThrowsError(
            try MirrorContainer.encrypt(payloads: [:], passphrase: "x",
                                        salt: Data(repeating: 0, count: 15)))
        XCTAssertThrowsError(
            try MirrorContainer.encrypt(payloads: [.kdbx: Data([0x00])], passphrase: "",
                                        salt: Self.fixtureSalt))
    }

    // MARK: - One-time vector regeneration

    func testGenerateVectorsWhenRequested() throws {
        try XCTSkipUnless(Self.generateVectors, "GENERATE_VECTORS=1 only")
        let container = try Self.fixtureContainer()
        print("CANONICAL_PREFIX_HEX=\(String(container.hexString.prefix(74))) LEN=\(container.count)")
    }
}

private extension Data {
    var hexString: String {
        // Int() promotion: a raw UInt8 CVarArg traps String(format:) on
        // Apple Silicon ("Not enough bits to represent the passed value").
        map { String(format: "%02x", Int($0)) }.joined()
    }
}
