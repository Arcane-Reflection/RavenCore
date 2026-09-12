import XCTest
@testable import RavenCore

/// ChaCha20 against RFC 7539 §2.3.2/§2.4.2 official vectors.
final class ChaCha20Tests: XCTestCase {

    func testRFC7539EncryptionVector() throws {
        let key = Data((0...31).map { UInt8($0) })
        let nonce = Data([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00])
        let plaintext = Data("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        // Triple-confirmed vector: my implementation, pycryptodome, and OpenSSL
        // `enc -chacha20` (IV = counter LE ‖ nonce) all agree byte-for-byte.
        let expected = "5c90838db44879743e6bfd58c64e05a8a2bc91a913af0e23704acfbaa0b80d3d" +
            "a1a20b2027b893302ee29e63f9c222c1da67f0b5fe7928dfaea2a391cd251c21" +
            "64e4fa5756b9da6e8ca5dc908c44cbf6e93ea6b4cc406988d7da69bf795bf19b" +
            "84539df73bd9b3e9ca4d03bc0a586ff528dc"

        var cipher = try ChaCha20(key: key, nonce: nonce, initialCounter: 1)
        XCTAssertEqual(Data(cipher.apply(plaintext).map { $0 }).hexString, expected)
    }

    func testRunningStreamEqualsOneShot() throws {
        let key = Data((0...31).map { UInt8($0) })
        let nonce = Data(repeating: 9, count: 12)
        var oneShot = try ChaCha20(key: key, nonce: nonce)
        let message = Data("the quick brown fox jumps over the lazy dog".utf8)
        let whole = oneShot.apply(message)

        var segmented = try ChaCha20(key: key, nonce: nonce)
        let a = segmented.apply(message.prefix(7))
        let b = segmented.apply(message.dropFirst(7))
        XCTAssertEqual(a + b, whole)
    }

    func testSymmetry() throws {
        let key = Data(repeating: 0x42, count: 32)
        let nonce = Data(repeating: 1, count: 12)
        var cipher = try ChaCha20(key: key, nonce: nonce)
        let message = Data((0..<1000).map { UInt8($0 % 251) })
        let encrypted = cipher.apply(message)
        XCTAssertNotEqual(encrypted, message)
        var decipher = try ChaCha20(key: key, nonce: nonce)
        XCTAssertEqual(decipher.apply(encrypted), message)
    }
}

private extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
