import Foundation

/// KDBX value-protection stream (keepass.info 4.1 spec §"Inner Encryption").
///
/// A stream cipher whose state advances across ALL protected values of the
/// document in document order — segment-wise consumption must equal one-shot
/// consumption or every later value decrypts to garbage (threat T-02-05).
///
/// Parameters per spec:
/// - Salsa20 (id 2): K is 32 bytes → key = SHA-256(K), nonce = E830094B97205D2A
/// - ChaCha20 (id 3): K is 64 bytes → H = SHA-512(K), key = H[0..31], nonce = H[32..43]
public final class KdbxProtectedStream {
    private var cipher: (Data) -> Data

    /// - Parameters:
    ///   - id: inner stream algorithm (Salsa20 for 3.1, ChaCha20 for 4.x).
    ///   - key: inner stream key from the inner header (32 or 64 bytes).
    public init(id: KdbxInnerHeader.InnerStreamID, key: Data) throws {
        switch id {
        case .salsa20:
            guard key.count == 32 else { throw KdbxError.malformedData }
            var salsa = try Salsa20(key: Hmac.sha256(key), nonce: Data([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]))
            cipher = { salsa.apply($0) }
        case .chacha20:
            guard key.count == 64 else { throw KdbxError.malformedData }
            let h = Hmac.sha512(key)
            // Spec (keepass.info §Inner Encryption): key = H[0..31], nonce =
            // H[32..43]. NOT the digest suffix — slicing H[32..<44] is
            // load-bearing (caught by KeePassXC content verification, Phase 1 UAT).
            var chacha = try ChaCha20(key: Data(h.prefix(32)), nonce: Data(h[32..<44]))
            cipher = { chacha.apply($0) }
        case .arcFourVariant:
            throw KdbxError.unsupportedCipher
        }
    }

    /// Encrypts/decrypts one protected value; the stream state keeps advancing
    /// across calls. Caller responsibility: document order.
    public func process(_ value: Data) -> Data {
        cipher(value)
    }
}
