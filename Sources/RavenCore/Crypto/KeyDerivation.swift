import CArgon2
import CommonCrypto
import Foundation

/// Errors thrown by `KeyDerivation`. All `Equatable` for exact-case test
/// assertions; `invalidParameter` never carries the offending values.
public enum KeyDerivationError: Error, Equatable {
    case invalidParameter
    case derivationFailed(status: Int32)
}

/// Password-based key derivation.
///
/// Argon2id (default, v1.1 format) via the vendored reference implementation
/// (pin: `Sources/CArgon2/UPSTREAM.md`). PBKDF2-HMAC-SHA256 is retained
/// permanently as the version-1 unlock path — old vaults stay openable
/// (01-CONTEXT.md D-04).
public enum KeyDerivation {

    // MARK: - Argon2id (v1.1 default)

    /// Default Argon2id parameters for newly created vaults (D-01: single
    /// default, no presets in v1.1). Sized to stay sub-second and far below
    /// iOS jetsam limits (research PITFALLS #6).
    public static let argon2MemoryKiB = 65_536
    /// Argon2id time cost (D-01).
    public static let argon2TimeCost = 3
    /// Argon2id parallelism (D-01).
    public static let argon2Parallelism = 2

    /// Derives a 32-byte Argon2d key (version 0x13). Same reference core as
    /// Argon2id with type 0 — required to read legacy KDF choices in kdbx files.
    public static func argon2d(
        password: Data,
        salt: Data,
        memoryKiB: Int,
        timeCost: Int,
        parallelism: Int
    ) throws -> Data {
        try argon2HashRaw(password: password, salt: salt, memoryKiB: memoryKiB,
                          timeCost: timeCost, parallelism: parallelism, type: Argon2_d)
    }

    /// Derives a 32-byte Argon2id key (version 0x13, no secret/associated data).
    public static func argon2id(
        password: Data,
        salt: Data,
        memoryKiB: Int,
        timeCost: Int,
        parallelism: Int
    ) throws -> Data {
        try argon2HashRaw(password: password, salt: salt, memoryKiB: memoryKiB,
                          timeCost: timeCost, parallelism: parallelism, type: Argon2_id)
    }

    private static func argon2HashRaw(
        password: Data,
        salt: Data,
        memoryKiB: Int,
        timeCost: Int,
        parallelism: Int,
        type: Argon2_type
    ) throws -> Data {
        // Guards cover native vault creation (D-01: p=2) and kdbx interop
        // reads (desktop-created files may use higher parallelism/memory).
        // Lower memory bound is the Argon2 spec floor (8·p KiB — the vendored
        // C core enforces the p factor itself); it deliberately matches the
        // kdbx-layer clamp in KdbxKeyComponents so both layers agree and no
        // foreign error type can escape at the seam (02-REVIEW-FULL FW-03).
        // The timeCost ceiling guards the UInt32 cast below against silent
        // truncation (FI-08 / I-01 family).
        guard !password.isEmpty, !salt.isEmpty,
              memoryKiB >= 8, memoryKiB <= 4_194_304,
              timeCost >= 1, timeCost <= Int(UInt32.max),
              parallelism >= 1, parallelism <= 16 else {
            throw KeyDerivationError.invalidParameter
        }
        var output = Data(repeating: 0, count: 32)
        let status: Int32 = output.withUnsafeMutableBytes { outputBuffer in
            password.withUnsafeBytes { passwordBuffer in
                salt.withUnsafeBytes { saltBuffer in
                    if type == Argon2_id {
                        return argon2id_hash_raw(
                            UInt32(timeCost), UInt32(memoryKiB), UInt32(parallelism),
                            passwordBuffer.baseAddress, password.count,
                            saltBuffer.baseAddress, salt.count,
                            outputBuffer.baseAddress, 32
                        )
                    }
                    return argon2d_hash_raw(
                        UInt32(timeCost), UInt32(memoryKiB), UInt32(parallelism),
                        passwordBuffer.baseAddress, password.count,
                        saltBuffer.baseAddress, salt.count,
                        outputBuffer.baseAddress, 32
                    )
                }
            }
        }
        guard status == Int32(ARGON2_OK.rawValue) else { throw KeyDerivationError.derivationFailed(status: status) }
        return output
    }

    // MARK: - PBKDF2 (legacy, version-1 format — kept forever)

    /// Default PBKDF2 iteration count for newly created (version-1) vaults.
    public static let recommendedIterations = 600_000
    /// Floor accepted by the PBKDF2 paths.
    public static let minimumIterations = 100_000

    /// Derives a key of `outputLength` bytes from `password` and `salt`.
    public static func pbkdf2SHA256(
        password: Data,
        salt: Data,
        iterations: Int = recommendedIterations,
        outputLength: Int = 32
    ) throws -> Data {
        guard !password.isEmpty, !salt.isEmpty,
              iterations >= 1, outputLength >= 16 else {
            throw KeyDerivationError.invalidParameter
        }
        var output = Data(repeating: 0, count: outputLength)
        let status = output.withUnsafeMutableBytes { outputBuffer in
            password.withUnsafeBytes { passwordBuffer in
                salt.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        password.count,
                        saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        outputBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        outputLength
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw KeyDerivationError.derivationFailed(status: status) }
        return output
    }

    /// Derives a key of `outputLength` bytes with PBKDF2-HMAC-SHA512.
    ///
    /// BIP39 mnemonic→seed derivation only (CORE-09; 02-CONTEXT.md D-07):
    /// password = NFKD(mnemonic), salt = "mnemonic" + NFKD(passphrase),
    /// 2048 iterations, 64-byte output. The sibling `pbkdf2SHA256` above is
    /// the frozen version-1 legacy unlock path (Phase 1 format stability) —
    /// this function is additive and must never replace or alter it. Unlike
    /// the frozen sibling, an upper iterations bound precedes the UInt32
    /// cast so absurd values fail typed instead of truncating (02-REVIEW.md
    /// I-01).
    public static func pbkdf2SHA512(
        password: Data,
        salt: Data,
        iterations: Int = recommendedIterations,
        outputLength: Int = 32
    ) throws -> Data {
        guard !password.isEmpty, !salt.isEmpty,
              iterations >= 1, iterations <= Int(UInt32.max), outputLength >= 16 else {
            throw KeyDerivationError.invalidParameter
        }
        var output = Data(repeating: 0, count: outputLength)
        let status = output.withUnsafeMutableBytes { outputBuffer in
            password.withUnsafeBytes { passwordBuffer in
                salt.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        password.count,
                        saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        UInt32(iterations),
                        outputBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        outputLength
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw KeyDerivationError.derivationFailed(status: status) }
        return output
    }
}
