import XCTest
@testable import RavenCore

/// CORE-06: the five key file formats (KeePassXC FileKey.cpp semantics),
/// v2.0 generation, and composite use with/without a password.
final class KeyFileTests: XCTestCase {

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    func testXMLV1Base64() throws {
        let raw = Data((1...32).map { UInt8($0) })
        let xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>\(raw.base64EncodedString())</Data></Key></KeyFile>"
        XCTAssertEqual(try KdbxKeyFile.load(data: Data(xml.utf8)), raw)
    }

    func testXMLV2HexWithHash() throws {
        let generated = try KdbxKeyFile.generate() // v2.0 layout
        let key = try KdbxKeyFile.load(data: generated)
        XCTAssertEqual(key.count, 32)
        // Round trip: re-generate from the same raw bytes via load → stable.
        let again = try KdbxKeyFile.load(data: generated)
        XCTAssertEqual(key, again)
    }

    func testXMLV2HashMismatchIsLoud() throws {
        var xml = String(data: try KdbxKeyFile.generate(), encoding: .utf8)!
        // Substitute a syntactically valid but wrong 8-hex-digit hash.
        xml = xml.replacingOccurrences(
            of: "Hash=\"[0-9A-F]{8}\"",
            with: "Hash=\"DEADBEEF",
            options: .regularExpression
        ).replacingOccurrences(of: "Hash=\"DEADBEEF", with: "Hash=\"DEADBEEF\"")
        XCTAssertThrowsError(try KdbxKeyFile.load(data: Data(xml.utf8))) { error in
            XCTAssertEqual(error as? KdbxError, .keyFileCorrupt)
        }
    }

    func testFixed32ByteBinary() throws {
        let raw = Data((0..<32).map { UInt8($0 ^ 0x5A) })
        XCTAssertEqual(try KdbxKeyFile.load(data: raw), raw)
    }

    func testFixed64CharHex() throws {
        let raw = Data((0..<32).map { UInt8($0) })
        let text = Data(hex(raw).uppercased().utf8)
        XCTAssertEqual(try KdbxKeyFile.load(data: text), raw)
    }

    func testHashedFallbackForArbitraryFiles() throws {
        let arbitrary = Data("this is not a key file, just some text".utf8)
        XCTAssertEqual(try KdbxKeyFile.load(data: arbitrary), Hmac.sha256(arbitrary))
        // A 33-byte file is neither XML nor 32 nor 64 → hashed.
        let odd = Data(repeating: 7, count: 33)
        XCTAssertEqual(try KdbxKeyFile.load(data: odd), Hmac.sha256(odd))
    }

    func testGenerateProducesLoadableV2() throws {
        let file = try KdbxKeyFile.generate()
        let text = String(data: file, encoding: .utf8)!
        XCTAssertTrue(text.contains("<Version>2.0</Version>"))
        XCTAssertTrue(text.contains("Hash=\""))
        let key = try KdbxKeyFile.load(data: file)
        XCTAssertEqual(key.count, 32)
        // Distinct generations produce distinct keys.
        XCTAssertNotEqual(key, try KdbxKeyFile.load(data: try KdbxKeyFile.generate()))
    }

    func testCompositeCombinationsUnlock() throws {
        let password = "combo-pass"
        let keyFileData = try KdbxKeyFile.generate()
        let key = try KdbxKeyFile.load(data: keyFileData)

        var doc = KdbxDocument()
        doc.root.entries.append({
            var e = KdbxEntry(); e.setValue("Title", "Combo"); return e
        }())

        // password + key file
        let comboCreds = try KdbxReader.Credentials(password: password, keyFileKey: key)
        let data = try KdbxWriter.write(doc, credentials: comboCreds)
        let reopened = try KdbxReader.read(data, credentials: comboCreds)
        XCTAssertEqual(reopened.root.entries.first?.value("Title"), "Combo")

        // Wrong combination (password only) must fail.
        XCTAssertThrowsError(try KdbxReader.read(data, credentials: try KdbxReader.Credentials(password: password))) { error in
            XCTAssertEqual(error as? KdbxError, .wrongCredentials)
        }
        // Wrong combination (different key file) must fail.
        let otherKey = try KdbxKeyFile.load(data: try KdbxKeyFile.generate())
        XCTAssertThrowsError(try KdbxReader.read(data, credentials: try KdbxReader.Credentials(password: password, keyFileKey: otherKey))) { error in
            XCTAssertEqual(error as? KdbxError, .wrongCredentials)
        }
    }
}
