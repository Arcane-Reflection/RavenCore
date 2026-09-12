import Foundation

/// Errors thrown by the Keepass module. All `Equatable` for exact-case test
/// assertions, mirroring the engine's per-module error enum convention.
public enum KdbxError: Error, Equatable {
    /// File structure is unreadable (bad signature, truncated stream, HMAC mismatch).
    case corruptFile
    /// Version critical-byte above the supported range.
    case unsupportedVersion(UInt32)
    /// Composite key did not open the database (uniform: never distinguish
    /// wrong password vs wrong key file from an attacker's view).
    case wrongCredentials
    /// Unknown outer cipher UUID or inner stream id.
    case unsupportedCipher
    /// Unknown KDF UUID in header field 11.
    case unsupportedKdf
    /// KDF parameters missing, out of supported bounds, or malformed.
    case unsupportedKdfParameters
    /// Attachment above the configured limit (D-07: loud error, never truncation).
    case attachmentTooLarge(limitBytes: Int)
    /// Generic malformed input (bad length prefix, missing terminator, …).
    case malformedData
    /// Key file v2.0 integrity hash mismatch or unparsable key data.
    case keyFileCorrupt
    /// Key file XML version is neither 1.0 nor 2.0.
    case unsupportedKeyFile
}
