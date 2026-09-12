import CryptoKit
import Foundation

/// A provider that can wrap (encrypt) and unwrap (decrypt) the vault's data key.
///
/// The v1.1 dual-wrap design stores the data key wrapped by **both**:
/// 1. a Secure Enclave key (device-bound, convenience path) — provider ships with the app target
/// 2. a passphrase-derived KEK (portable path) — enables migration to a new device
///
/// Either wrap alone opens the vault.
public protocol WrappingKeyProvider {
    func wrap(_ key: SymmetricKey) throws -> SealedPayload
    func unwrap(_ payload: SealedPayload) throws -> SymmetricKey
}

/// Wraps the data key under a passphrase-derived KEK (PBKDF2-HMAC-SHA256).
/// This is the portable half of the dual-wrap pair.
public struct PassphraseWrapProvider: WrappingKeyProvider {
    private let kek: SymmetricKey

    /// Derives the KEK from `passphrase` (PBKDF2-HMAC-SHA256, 600k default).
    public init(passphrase: String, salt: Data, iterations: Int = KeyDerivation.recommendedIterations) throws {
        let kekData = try KeyDerivation.pbkdf2SHA256(password: Data(passphrase.utf8), salt: salt, iterations: iterations)
        self.kek = SymmetricKey(data: kekData)
    }

    /// Rehydrates a provider from already-derived KEK bytes.
    public init(rawKEK: Data) {
        self.kek = SymmetricKey(data: rawKEK)
    }

    /// Encrypts the key’s raw bytes under this provider’s KEK.
    public func wrap(_ key: SymmetricKey) throws -> SealedPayload {
        try AESGCMCipher.encrypt(key.rawRepresentation, key: kek)
    }

    /// Decrypts a sealed payload back into the wrapped key.
    public func unwrap(_ payload: SealedPayload) throws -> SymmetricKey {
        SymmetricKey(data: try AESGCMCipher.decrypt(payload, key: kek))
    }
}

/// Wraps the data key under an in-memory symmetric key.
/// Used by tests and as the internal plumbing for the future Secure Enclave provider.
public struct RawKeyWrapProvider: WrappingKeyProvider {
    private let wrappingKey: SymmetricKey

    /// Creates a provider over an in-memory key (test stand-in for the
    /// future Secure Enclave provider, which ships with the app target).
    public init(key: SymmetricKey) {
        self.wrappingKey = key
    }

    /// Encrypts the key’s raw bytes under the wrapping key.
    public func wrap(_ key: SymmetricKey) throws -> SealedPayload {
        try AESGCMCipher.encrypt(key.rawRepresentation, key: wrappingKey)
    }

    /// Decrypts a sealed payload back into the wrapped key.
    public func unwrap(_ payload: SealedPayload) throws -> SymmetricKey {
        SymmetricKey(data: try AESGCMCipher.decrypt(payload, key: wrappingKey))
    }
}

extension SymmetricKey {
    /// Raw bytes of the key. Handle the result as secret material (zero after use).
    public var rawRepresentation: Data {
        withUnsafeBytes { Data($0) }
    }
}
