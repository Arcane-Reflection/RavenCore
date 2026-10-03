import CryptoKit
import Foundation

/// CryptoKit HMAC thin wrappers (KDBX 4 header + block authentication).
public enum Hmac {
    /// HMAC-SHA-256 over `message` under `key`.
    public static func hmacSHA256(key: Data, message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: [UInt8](message), using: SymmetricKey(data: key)))
    }

    /// HMAC-SHA-512 over `message` under `key`.
    public static func hmacSHA512(key: Data, message: Data) -> Data {
        Data(HMAC<SHA512>.authenticationCode(for: [UInt8](message), using: SymmetricKey(data: key)))
    }

    /// SHA-256 digest.
    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// SHA-512 digest.
    public static func sha512(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    /// Constant-time equality for MAC/tag/hash comparison (02-REVIEW-FULL
    /// FI-04).
    ///
    /// Every comparison site faces attacker-positioned bytes under a
    /// secret-derived key; `==`/`memcmp` may short-circuit on the first
    /// differing byte, which is a timing oracle in principle. For a local
    /// file parser this is impractical to exploit, so it is
    /// defense-in-depth — but cheap to do right: one XOR fold with no
    /// data-dependent early exit. (Scalar comparisons such as the gzip
    /// CRC-32/ISIZE words compile to a single unbranching machine compare
    /// and need no equivalent.)
    public static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var delta: UInt8 = 0
        for (a, b) in zip(lhs, rhs) { delta |= a ^ b }
        return delta == 0
    }
}
