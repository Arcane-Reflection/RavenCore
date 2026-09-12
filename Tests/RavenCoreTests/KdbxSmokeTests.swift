import XCTest
@testable import RavenCore

/// End-to-end smoke: self-generated minimal databases across the cipher/KDF
/// matrix, gzip on/off, write → read round trip, wrong-credential rejection.
final class KdbxSmokeTests: XCTestCase {

    private let password = "correct horse battery staple"

    func makeDocument() -> KdbxDocument {
        var doc = KdbxDocument()
        doc.meta.generator = "RavenVault"
        doc.meta.databaseName = "Smoke"
        doc.meta.recycleBinEnabled = false

        var times = KdbxTimes()
        times.creationTime = Date(timeIntervalSince1970: 1_700_000_000)
        times.lastModificationTime = times.creationTime
        times.expires = false
        times.usageCount = 0

        var root = KdbxGroup(name: "Root")
        root.uuid = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        root.times = times
        root.isExpanded = true

        var group = KdbxGroup(name: "Web")
        group.uuid = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!

        var entry = KdbxEntry()
        entry.uuid = UUID(uuidString: "99999999-8888-7777-6666-555555555555")!
        entry.times = times
        entry.setValue("Title", "Example")
        entry.setValue("UserName", "user@example.com")
        entry.setValue("Password", "s3cr3t-π-value", protected: true)
        entry.setValue("Notes", "line1\nline2 <with> & symbols")
        group.entries.append(entry)
        root.groups.append(group)
        doc.root = root
        return doc
    }

    private func options(cipher: UUID, argon2: Bool, gzip: Bool) -> KdbxWriter.Options {
        var options = argon2 ? KdbxWriter.Options.argon2idDefaults() : KdbxWriter.Options.aesKdf(rounds: 10_000)
        options.cipherId = cipher
        options.compression = gzip ? .gzip : .none
        return options
    }

    func testCipherKDFMatrixRoundTrip() throws {
        let matrix: [(cipher: UUID, argon2: Bool, gzip: Bool)] = [
            (KdbxCrypto.aesCipherUUID, true, true),
            (KdbxCrypto.aesCipherUUID, false, false),
            (KdbxCrypto.chacha20CipherUUID, true, true),
            (KdbxCrypto.chacha20CipherUUID, false, false),
        ]
        let expected = makeDocument()
        for kase in matrix {
            let credentials = try KdbxReader.Credentials(password: password)
            let data = try KdbxWriter.write(expected, credentials: credentials, options: options(cipher: kase.cipher, argon2: kase.argon2, gzip: kase.gzip))

            // Signature + version sanity.
            var reader = ByteReader(data)
            XCTAssertEqual(try reader.readUInt32(), KdbxOuterHeader.signature1)
            XCTAssertEqual(try reader.readUInt32(), KdbxOuterHeader.signature2)
            XCTAssertEqual(try reader.readUInt32(), KdbxOuterHeader.version40)

            let reopened = try KdbxReader.read(data, credentials: credentials)
            XCTAssertEqual(reopened.root.name, expected.root.name)
            XCTAssertEqual(reopened.root.groups.count, 1)
            let entry = try XCTUnwrap(reopened.root.groups.first?.entries.first)
            XCTAssertEqual(entry.value("Title"), "Example")
            XCTAssertEqual(entry.value("UserName"), "user@example.com")
            XCTAssertEqual(entry.value("Password"), "s3cr3t-π-value")
            XCTAssertEqual(entry.value("Notes"), "line1\nline2 <with> & symbols")
        }
    }

    func testWrongCredentialsRejected() throws {
        let credentials = try KdbxReader.Credentials(password: password)
        let data = try KdbxWriter.write(makeDocument(), credentials: credentials)
        XCTAssertThrowsError(try KdbxReader.read(data, credentials: try KdbxReader.Credentials(password: "wrong"))) { error in
            XCTAssertEqual(error as? KdbxError, .wrongCredentials)
        }
    }

    func testKeyFileOnlyCredentials() throws {
        let key = SecureRandom.bytes(count: 32)
        let credentials = try KdbxReader.Credentials(keyFileKey: key)
        let data = try KdbxWriter.write(makeDocument(), credentials: credentials)
        let reopened = try KdbxReader.read(data, credentials: try KdbxReader.Credentials(keyFileKey: key))
        XCTAssertEqual(reopened.root.groups.first?.entries.first?.value("Title"), "Example")
        XCTAssertThrowsError(try KdbxReader.read(data, credentials: try KdbxReader.Credentials(keyFileKey: SecureRandom.bytes(count: 32)))) { error in
            XCTAssertEqual(error as? KdbxError, .wrongCredentials)
        }
    }

    func testUnknownOuterCipherRejected() throws {
        // A document written with an unknown cipher UUID must fail dispatch.
        var writer = ByteWriter()
        writer.writeUInt32(KdbxOuterHeader.signature1)
        writer.writeUInt32(KdbxOuterHeader.signature2)
        writer.writeUInt32(KdbxOuterHeader.version40)
        writer.writeUInt8(2) // CipherID
        writer.writeInt32(16)
        writer.writeBytes(Data(repeating: 0x01, count: 16))
        writer.writeUInt8(0) // end of header
        writer.writeInt32(0)
        let header = try KdbxOuterHeader.read(writer.data)
        XCTAssertThrowsError(try KdbxCrypto.outerCrypt(
            Data(repeating: 0, count: 32), cipherId: header.cipherId,
            key: Data(repeating: 0, count: 32), iv: Data(repeating: 0, count: 16), encrypt: false
        )) { error in
            XCTAssertEqual(error as? KdbxError, .unsupportedCipher)
        }
    }
}
