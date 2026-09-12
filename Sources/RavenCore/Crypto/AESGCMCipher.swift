import CryptoKit
import Foundation

/// Errors thrown by the low-level crypto helpers.
public enum RavenCryptoError: Error, Equatable {
    case sealFailed
    case invalidCiphertext
}

/// A sealed payload with the nonce stored alongside the ciphertext.
///
/// Wire layout note: `ciphertext` holds `ciphertext || 16-byte GCM tag`
/// (CryptoKit's "combined" representation minus the 12-byte nonce), which
/// mirrors the v1.1 data model's `nonce` / `payload` separation.
public struct SealedPayload: Sendable, Equatable, Codable {
    /// 12-byte AES-GCM nonce, stored beside the ciphertext.
    public var nonce: Data
    /// `ciphertext ‖ 16-byte GCM tag` (CryptoKit "combined" minus the nonce).
    public var ciphertext: Data

    /// Creates a sealed payload from its wire parts.
    public init(nonce: Data, ciphertext: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
    }
}

/// AES-256-GCM authenticated encryption (Apple CryptoKit, no custom cryptography).
public enum AESGCMCipher {

    /// Encrypts `plaintext` under `key` with a fresh random 12-byte nonce.
    public static func encrypt(_ plaintext: Data, key: SymmetricKey) throws -> SealedPayload {
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw RavenCryptoError.sealFailed }
        let nonce = sealed.nonce.withUnsafeBytes { Data($0) }
        return SealedPayload(
            nonce: nonce,
            ciphertext: Data(combined.dropFirst(12))
        )
    }

    /// Decrypts a sealed payload. Throws on tag mismatch (wrong key or tampering).
    ///
    /// Every failure path maps to `RavenCryptoError.invalidCiphertext`
    /// (02-REVIEW-FULL FI-06): raw CryptoKit errors (undersized combined
    /// payload, GCM tag failure) never escape the module's typed-error
    /// convention.
    public static func decrypt(_ payload: SealedPayload, key: SymmetricKey) throws -> Data {
        guard payload.nonce.count == 12 else { throw RavenCryptoError.invalidCiphertext }
        let combined = payload.nonce + payload.ciphertext
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(box, using: key)
        } catch {
            throw RavenCryptoError.invalidCiphertext
        }
    }
}
