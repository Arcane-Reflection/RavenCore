import CryptoKit
import XCTest
@testable import RavenCore

final class AESGCMCipherTests: XCTestCase {

    func testRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("the raven never forgets 🐦‍⬛".utf8)
        let sealed = try AESGCMCipher.encrypt(plaintext, key: key)
        let decrypted = try AESGCMCipher.decrypt(sealed, key: key)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testNonceIsRandomPerEncryption() throws {
        let key = SymmetricKey(size: .bits256)
        let first = try AESGCMCipher.encrypt(Data("a".utf8), key: key)
        let second = try AESGCMCipher.encrypt(Data("a".utf8), key: key)
        XCTAssertNotEqual(first.nonce, second.nonce)
        XCTAssertEqual(first.nonce.count, 12)
    }

    func testTamperedCiphertextFailsAuthentication() throws {
        let key = SymmetricKey(size: .bits256)
        var sealed = try AESGCMCipher.encrypt(Data("secret".utf8), key: key)
        sealed.ciphertext[sealed.ciphertext.count - 1] ^= 0xFF
        XCTAssertThrowsError(try AESGCMCipher.decrypt(sealed, key: key))
    }

    func testWrongKeyFails() throws {
        let sealed = try AESGCMCipher.encrypt(Data("secret".utf8), key: SymmetricKey(size: .bits256))
        XCTAssertThrowsError(try AESGCMCipher.decrypt(sealed, key: SymmetricKey(size: .bits256)))
    }

    func testInvalidNonceLengthRejected() throws {
        let key = SymmetricKey(size: .bits256)
        let payload = SealedPayload(nonce: Data(repeating: 0, count: 8), ciphertext: Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try AESGCMCipher.decrypt(payload, key: key))
    }

    /// FI-06: failure paths that CryptoKit would surface as raw CryptoKitError
    /// are mapped to the module's typed error.
    func testUndersizedCiphertextThrowsTypedError() throws {
        let key = SymmetricKey(size: .bits256)
        // 12-byte nonce + 8-byte "ciphertext": below the 16-byte GCM tag, so
        // SealedBox(combined:) init fails inside CryptoKit.
        let payload = SealedPayload(nonce: Data(repeating: 1, count: 12), ciphertext: Data(repeating: 2, count: 8))
        XCTAssertThrowsError(try AESGCMCipher.decrypt(payload, key: key)) { error in
            XCTAssertEqual(error as? RavenCryptoError, .invalidCiphertext)
        }
    }

    func testTagFailureThrowsTypedError() throws {
        let key = SymmetricKey(size: .bits256)
        var sealed = try AESGCMCipher.encrypt(Data("secret".utf8), key: key)
        sealed.ciphertext[0] ^= 0xFF
        XCTAssertThrowsError(try AESGCMCipher.decrypt(sealed, key: key)) { error in
            XCTAssertEqual(error as? RavenCryptoError, .invalidCiphertext)
        }
    }

    func testWrongKeyThrowsTypedError() throws {
        let sealed = try AESGCMCipher.encrypt(Data("secret".utf8), key: SymmetricKey(size: .bits256))
        XCTAssertThrowsError(try AESGCMCipher.decrypt(sealed, key: SymmetricKey(size: .bits256))) { error in
            XCTAssertEqual(error as? RavenCryptoError, .invalidCiphertext)
        }
    }
}

final class KeyDerivationTests: XCTestCase {

    func testDeterministicOutput() throws {
        let salt = SecureRandom.bytes(count: 16)
        let a = try KeyDerivation.pbkdf2SHA256(password: Data("gibberish".utf8), salt: salt, iterations: 10_000)
        let b = try KeyDerivation.pbkdf2SHA256(password: Data("gibberish".utf8), salt: salt, iterations: 10_000)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.count, 32)
    }

    func testDifferentSaltYieldsDifferentKey() throws {
        let a = try KeyDerivation.pbkdf2SHA256(password: Data("gibberish".utf8), salt: SecureRandom.bytes(count: 16), iterations: 10_000)
        let b = try KeyDerivation.pbkdf2SHA256(password: Data("gibberish".utf8), salt: SecureRandom.bytes(count: 16), iterations: 10_000)
        XCTAssertNotEqual(a, b)
    }

    func testIterationsChangeOutput() throws {
        let salt = SecureRandom.bytes(count: 16)
        let a = try KeyDerivation.pbkdf2SHA256(password: Data("gibberish".utf8), salt: salt, iterations: 10_000)
        let b = try KeyDerivation.pbkdf2SHA256(password: Data("gibberish".utf8), salt: salt, iterations: 20_000)
        XCTAssertNotEqual(a, b)
    }

    func testProductionIterationCountCompletes() throws {
        // 600k iterations (v1.1 spec): must complete in CI on Apple Silicon.
        let start = Date()
        _ = try KeyDerivation.pbkdf2SHA256(password: Data("gibberish".utf8), salt: SecureRandom.bytes(count: 16))
        XCTAssertLessThan(Date().timeIntervalSince(start), 10)
    }

    func testEmptyPasswordRejected() {
        XCTAssertThrowsError(try KeyDerivation.pbkdf2SHA256(password: Data(), salt: SecureRandom.bytes(count: 16), iterations: 1_000))
    }

    /// FI-08/I-01 family: values beyond UInt32.max must fail typed, not
    /// silently truncate at the CC cast (deriving with far fewer rounds than
    /// requested).
    func testArgon2TimeCostAboveUInt32Rejected() {
        XCTAssertThrowsError(try KeyDerivation.argon2id(
            password: Data("pw".utf8), salt: Data(repeating: 1, count: 8),
            memoryKiB: 65_536, timeCost: Int(UInt32.max) + 3, parallelism: 1
        )) { XCTAssertEqual($0 as? KeyDerivationError, .invalidParameter) }
    }

    /// I-01: pbkdf2SHA512 (unlike the frozen pbkdf2SHA256) guards the UInt32
    /// cast explicitly.
    func testPbkdf2SHA512IterationsAboveUInt32Rejected() {
        XCTAssertThrowsError(try KeyDerivation.pbkdf2SHA512(
            password: Data("pw".utf8), salt: Data(repeating: 1, count: 8),
            iterations: Int(UInt32.max) + 1
        )) { XCTAssertEqual($0 as? KeyDerivationError, .invalidParameter) }
    }
}

final class WrappingKeyProviderTests: XCTestCase {

    func testPassphraseProviderRoundTrip() throws {
        let provider = try PassphraseWrapProvider(passphrase: "paper-gibberish", salt: SecureRandom.bytes(count: 16), iterations: 10_000)
        let dataKey = SymmetricKey(size: .bits256)
        let wrapped = try provider.wrap(dataKey)
        let unwrapped = try provider.unwrap(wrapped)
        XCTAssertEqual(unwrapped.rawRepresentation, dataKey.rawRepresentation)
    }

    func testRawKeyProviderRoundTrip() throws {
        let provider = RawKeyWrapProvider(key: SymmetricKey(size: .bits256))
        let dataKey = SymmetricKey(size: .bits256)
        let unwrapped = try provider.unwrap(try provider.wrap(dataKey))
        XCTAssertEqual(unwrapped.rawRepresentation, dataKey.rawRepresentation)
    }
}
