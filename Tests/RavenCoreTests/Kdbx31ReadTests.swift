import XCTest
@testable import RavenCore

/// KDBX 3.1 read path (D-05: unified document model). Builds a minimal 3.1
/// file byte-by-byte (signature, 2-byte-length header fields, AES-CBC,
/// StreamStartBytes, HashedBlockStream, Salsa20-protected values) and reads
/// it into the same model used for 4.x.
final class Kdbx31ReadTests: XCTestCase {

    func testMinimal31FileReadsIntoUnifiedModel() throws {
        let password = "legacy-v31-passphrase"
        let file = try makeV31File(password: password)
        let document = try KdbxReader.read(file, credentials: .init(password: password))
        XCTAssertEqual(document.version, .v31)
        XCTAssertEqual(document.root.name, "Legacy")
        let entry = try XCTUnwrap(document.root.entries.first)
        XCTAssertEqual(entry.value("Title"), "Old Entry")
        XCTAssertEqual(entry.value("Password"), "v31-secret")
    }

    /// Re-review follow-up 2 (Nyquist item 5): the 3.1 wrong-credential path.
    /// A StreamStartBytes mismatch must collapse to the uniform
    /// `wrongCredentials` — the same typed error the 4.x header-HMAC path
    /// produces — never a lower-level CBC/padding failure.
    func testWrongPasswordRejectedAsWrongCredentials() throws {
        let file = try makeV31File(password: "legacy-v31-passphrase")
        XCTAssertThrowsError(try KdbxReader.read(
            file, credentials: .init(password: "not-the-passphrase")
        )) { error in
            XCTAssertEqual(error as? KdbxError, .wrongCredentials)
        }
    }

    /// Uniformity, no oracle: with a two-component composite, poisoning
    /// either half produces the identical error — nothing outside the module
    /// can distinguish which half failed (credentials convention).
    func testEitherWrongCompositeHalfIsIndistinguishable() throws {
        let password = "legacy-v31-passphrase"
        let keyFileKey = SecureRandom.bytes(count: 32)
        let file = try makeV31File(password: password, keyFileKey: keyFileKey)

        var wrongPasswordError: Error?
        XCTAssertThrowsError(try KdbxReader.read(file, credentials: .init(
            password: "wrong-half", keyFileKey: keyFileKey
        ))) { wrongPasswordError = $0 }

        var wrongKeyFileError: Error?
        XCTAssertThrowsError(try KdbxReader.read(file, credentials: .init(
            password: password, keyFileKey: SecureRandom.bytes(count: 32)
        ))) { wrongKeyFileError = $0 }

        XCTAssertEqual(wrongPasswordError as? KdbxError, .wrongCredentials)
        XCTAssertEqual(wrongKeyFileError as? KdbxError, .wrongCredentials)
    }

    /// 3.1 carries `transformRounds` as a UInt64 header field while the AES-KDF
    /// bound is UInt32-scale (`KdbxReader.readV31`) — an absurd declared count
    /// must fail fast with the typed KDF error before any key derivation runs.
    func testTransformRoundsAboveUInt32Rejected() throws {
        let password = "legacy-v31-passphrase"
        let file = try makeV31File(password: password, declaredRounds: UInt64(UInt32.max) + 1)
        let credentials = try KdbxReader.Credentials(password: password)
        let start = Date()
        XCTAssertThrowsError(try KdbxReader.read(file, credentials: credentials)) { error in
            XCTAssertEqual(error as? KdbxError, .unsupportedKdfParameters)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
    }

    /// Writing a 3.1 document always produces 4.0 (D-05, never write 3.1).
    func testWriting31DocumentProducesV40() throws {
        var document = KdbxDocument()
        document.version = .v31
        document.root = KdbxGroup(name: "Upgraded")
        let credentials = try KdbxReader.Credentials(password: "pw")
        let data = try KdbxWriter.write(document, credentials: credentials)
        var reader = ByteReader(data)
        _ = try reader.readBytes(8)
        XCTAssertEqual(try reader.readUInt32(), KdbxOuterHeader.version40)
        let reopened = try KdbxReader.read(data, credentials: credentials)
        XCTAssertEqual(reopened.version, .v40)
        XCTAssertEqual(reopened.root.name, "Upgraded")
    }

    // MARK: - Helpers

    /// Builds the minimal 3.1 file shared by the positive read test and the
    /// negative (wrong-credential / hostile-KDF) tests. The header declares
    /// `declaredRounds`; the body is always sealed with a small sane round
    /// count so a hostile declared value stays cheap to construct (the
    /// reader rejects it before deriving anything).
    private func makeV31File(
        password: String,
        keyFileKey: Data? = nil,
        declaredRounds: UInt64 = 1_000
    ) throws -> Data {
        let masterSeed = SecureRandom.bytes(count: 32)
        let transformSeed = SecureRandom.bytes(count: 32)
        let iv = SecureRandom.bytes(count: 16)
        let streamStart = SecureRandom.bytes(count: 32)
        let protectedKey = SecureRandom.bytes(count: 32)

        // Minimal 3.1 XML with one protected value.
        let xml = """
        <?xml version="1.0" encoding="utf-8"?><KeePassFile><Meta><Generator>test</Generator></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Legacy</Name><Entry><UUID>BAAAAAAAAAAAAAAAAAAAAA==</UUID><String><Key>Title</Key><Value>Old Entry</Value></String><String><Key>Password</Key><Value Protected="True">\(base64OfProtected("v31-secret", key: protectedKey))</Value></String></Entry></Group></Root></KeePassFile>
        """

        // HashedBlockStream frame: [index][SHA-256][size][data], zero terminator.
        var hashed = ByteWriter()
        hashed.writeUInt32(0)
        hashed.writeBytes(Hmac.sha256(Data(xml.utf8)))
        hashed.writeInt32(Int32(xml.utf8.count))
        hashed.writeBytes(Data(xml.utf8))
        hashed.writeUInt32(1) // terminator block index increments (KeePassXC HashedBlockStream)
        hashed.writeBytes(Data(repeating: 0, count: 32))
        hashed.writeInt32(0)

        // Plaintext = StreamStartBytes ‖ hashed blocks.
        let plaintext = streamStart + hashed.data
        let composite = try KdbxReader.Credentials(password: password, keyFileKey: keyFileKey)
            .components()
            .compositeKey()
        let transformed = try AESECBCipher.aesKdf(key32: composite, seed: transformSeed, rounds: 1_000)
        let cipherKey = KdbxCrypto.cipherKey(masterSeed: masterSeed, transformedKey: transformed)
        let ciphertext = try AESECBCipher.encryptCBC(plaintext, key: cipherKey, iv: iv)

        // Header (2-byte lengths) with trailing SHA-256 in field 0.
        var headerBytes = ByteWriter()
        headerBytes.writeUInt32(KdbxOuterHeader.signature1)
        headerBytes.writeUInt32(KdbxOuterHeader.signature2)
        headerBytes.writeUInt32(KdbxOuterHeader.version31)
        writeField(&headerBytes, id: 2, value: KdbxCrypto.aesCipherUUID.data)
        writeField(&headerBytes, id: 4, value: masterSeed)
        writeField(&headerBytes, id: 5, value: transformSeed)
        var roundsBytes = ByteWriter()
        roundsBytes.writeUInt64(declaredRounds)
        writeField(&headerBytes, id: 6, value: roundsBytes.data)
        writeField(&headerBytes, id: 7, value: iv)
        writeField(&headerBytes, id: 8, value: protectedKey)
        writeField(&headerBytes, id: 9, value: streamStart)
        var salsaID = ByteWriter()
        salsaID.writeInt32(2)
        writeField(&headerBytes, id: 10, value: salsaID.data)

        let rawHeader = headerBytes.data
        var endField = ByteWriter()
        endField.writeUInt8(0)
        endField.writeUInt16(32)
        endField.writeBytes(Hmac.sha256(rawHeader))

        return rawHeader + endField.data + ciphertext
    }

    private func base64OfProtected(_ value: String, key: Data) -> String {
        var salsa = try! Salsa20(key: Hmac.sha256(key), nonce: Data([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]))
        return salsa.apply(Data(value.utf8)).base64EncodedString()
    }

    private func writeField(_ writer: inout ByteWriter, id: UInt8, value: Data) {
        writer.writeUInt8(id)
        writer.writeUInt16(UInt16(value.count))
        writer.writeBytes(value)
    }
}
