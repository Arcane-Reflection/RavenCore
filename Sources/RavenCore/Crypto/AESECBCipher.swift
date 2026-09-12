import CommonCrypto
import CryptoKit
import Foundation

/// AES-256 in ECB and CBC modes via CommonCrypto.
///
/// CryptoKit exposes AES-GCM only; KDBX needs CBC-PKCS7 for the outer cipher
/// and the ECB primitive for the legacy AES-KDF (composite key transformed by
/// `rounds` successive AES-256-ECB encryptions with the seed as key).
public enum AESECBCipher {

    /// AES-256-CBC with PKCS7 padding (KDBX 4 outer cipher, AES UUID).
    public static func encryptCBC(_ plaintext: Data, key: Data, iv: Data) throws -> Data {
        try cryptCBC(plaintext, key: key, iv: iv, encrypt: true)
    }

    /// Decrypts AES-256-CBC-PKCS7 ciphertext (KDBX 4 outer cipher, AES UUID).
    public static func decryptCBC(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        try cryptCBC(ciphertext, key: key, iv: iv, encrypt: false)
    }

    private static func cryptCBC(_ input: Data, key: Data, iv: Data, encrypt: Bool) throws -> Data {
        guard key.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            throw KdbxError.malformedData
        }
        var output = Data(count: input.count + kCCBlockSizeAES128)
        var moved = 0
        let status = output.withUnsafeMutableBytes { outBuf in
            input.withUnsafeBytes { inBuf in
                key.withUnsafeBytes { keyBuf in
                    iv.withUnsafeBytes { ivBuf in
                        CCCrypt(
                            encrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBuf.baseAddress, key.count,
                            ivBuf.baseAddress,
                            inBuf.baseAddress, input.count,
                            outBuf.baseAddress, outBuf.count,
                            &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw KdbxError.malformedData }
        output.removeSubrange(moved..<output.count)
        return output
    }

    /// Single AES-256-ECB block transformation (no padding — exactly 16 bytes).
    ///
    /// KDF/test primitive only: the live AES-KDF goes through the persistent
    /// cryptor in `aesKdf`. This exists so NIST SP 800-38A vectors and the
    /// one-round ECB identity check can anchor the KDF — deliberately not
    /// public API, keeping the package's raw-ECB surface internal
    /// (02-REVIEW-FULL FI-02).
    static func ecbEncryptBlock(_ block: Data, key: Data) throws -> Data {
        guard block.count == kCCBlockSizeAES128, key.count == kCCKeySizeAES256 else {
            throw KdbxError.malformedData
        }
        var output = Data(count: kCCBlockSizeAES128)
        var moved = 0
        let status = output.withUnsafeMutableBytes { outBuf in
            block.withUnsafeBytes { inBuf in
                key.withUnsafeBytes { keyBuf in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBuf.baseAddress, key.count,
                        nil,
                        inBuf.baseAddress, block.count,
                        outBuf.baseAddress, outBuf.count,
                        &moved
                    )
                }
            }
        }
        guard status == kCCSuccess, moved == kCCBlockSizeAES128 else { throw KdbxError.malformedData }
        return output
    }

    /// Pre-authentication DoS ceiling for AES-KDF round counts (T-02-03).
    ///
    /// The KDF transform runs BEFORE the header HMAC check, so a file's round
    /// count is hostile input. KeePassXC benchmark-calibrates AES-KDF rounds
    /// (≈ 142M on the development machine — the largest legitimately-created
    /// scale this ceiling must admit); `1 << 28` ≈ 2× that keeps every such
    /// file readable, while absurd hostile values (2^40+) fail fast as
    /// `KdbxError.unsupportedKdfParameters` instead of hanging the transform.
    /// Covered by both the KDBX 4 dispatch (`KdbxKeyComponents`) and the 3.1
    /// reader path.
    public static let maxKdfRounds: UInt64 = 1 << 28

    /// KDBX AES-KDF: the 32-byte composite key is encrypted `rounds` times
    /// with AES-256-ECB using the 32-byte seed as the key, then hashed once
    /// (KeePassXC AesKdf::transformKeyRaw — verified against 2.7.12).
    ///
    /// Uses a persistent CCCryptor: per-round key expansion (CCCrypt) made
    /// KeePassXC-default 142M-round files take ~15 minutes; a sustained
    /// context brings that to seconds. `rounds` above `maxKdfRounds` is
    /// rejected (pre-authentication DoS bound, see that constant).
    public static func aesKdf(key32: Data, seed: Data, rounds: UInt64) throws -> Data {
        guard key32.count == 32, seed.count == 32 else { throw KdbxError.malformedData }
        guard rounds >= 1, rounds <= maxKdfRounds else { throw KdbxError.unsupportedKdfParameters }
        var cryptor: CCCryptorRef?
        let createStatus = seed.withUnsafeBytes { keyBuf in
            CCCryptorCreateWithMode(
                CCOperation(kCCEncrypt), CCMode(kCCModeECB), CCAlgorithm(kCCAlgorithmAES),
                CCModeOptions(0), // kCCModeOptionECB_ECB raw value 0
                nil,
                keyBuf.baseAddress, seed.count,
                nil, 0, 0, 0, &cryptor
            )
        }
        guard createStatus == kCCSuccess, let cryptor else { throw KdbxError.malformedData }
        defer { CCCryptorRelease(cryptor) }

        var data = [UInt8](key32)
        var scratch = [UInt8](repeating: 0, count: 64)
        // Safe: `rounds <= maxKdfRounds` (1 << 28) is far below Int.max.
        let roundCount = Int(rounds)
        for _ in 0..<roundCount {
            var moved = 0
            let status = data.withUnsafeBufferPointer { dataBuf in
                scratch.withUnsafeMutableBytes { scratchBuf in
                    CCCryptorUpdate(cryptor, dataBuf.baseAddress, 32,
                                    scratchBuf.baseAddress, scratchBuf.count, &moved)
                }
            }
            // No explicit release here: the `defer` above owns the cryptor
            // (single ownership — releasing in both places would double-free
            // the C opaque handle if CCCryptorUpdate ever failed).
            guard status == kCCSuccess else {
                throw KdbxError.malformedData
            }
            data.replaceSubrange(0..<32, with: scratch.prefix(32))
        }
        return Hmac.sha256(Data(data))
    }
}

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
