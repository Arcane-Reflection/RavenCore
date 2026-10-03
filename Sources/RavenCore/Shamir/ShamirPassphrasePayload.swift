import Foundation

/// Errors thrown by the passphrase payload wrapper. All `Equatable` for
/// exact-case test assertions, mirroring the engine's per-module error enum
/// convention. No case carries passphrase material (T-07-01-04 convention).
public enum ShamirPassphrasePayloadError: Error, Equatable {
    /// The passphrase is empty — there is nothing to split.
    case empty
    /// The UTF-8 encoding exceeds 254 bytes (keeps the share value length
    /// within the paper format's 255-byte ceiling).
    case tooLong
    /// The byte string is not a `[1-byte length L][L bytes]` framing at all
    /// (trailing garbage, L inconsistent with the byte count).
    case malformed
    /// The bytes decoded to a String whose UTF-8 re-encoding differs from
    /// the input — reconstruction is reported honestly rather than surfacing
    /// mojibake as a passphrase.
    case notRoundTripping
}

/// Recovery secret framing for the Level 2 cold-storage ceremony (Phase 7
/// D-01): the Shamir shares encode **the vault master passphrase**.
///
/// Payload layout (1 byte overhead, self-delimiting):
///
///     [0]      length L  (big-endian, 1 ≤ L ≤ 254)
///     [1..L]   passphrase UTF-8 bytes, verbatim
///
/// The length prefix is required, not optional: without it a passphrase
/// whose UTF-8 ends in zero bytes would be ambiguous after reconstruction.
/// `L ≤ 254` keeps the share value length (L + 1) inside the paper format's
/// 255-byte bound, so every framed payload prints at a well-defined fixed
/// Crockford width.
///
/// **No NFC or any other normalization.** The bytes are the exact `String`
/// handed to `VaultService.unlock(serializedDocument:passphrase:)` — Swift
/// `String` is normalization-preserving, and normalizing one end only would
/// produce a passphrase that unlocks nothing. Decode validates the UTF-8
/// round-trip (re-encoding the reconstructed String must reproduce the input
/// bytes) before returning, so an unrecoverable String surfaces as
/// `notRoundTripping` rather than as mojibake.
public enum ShamirPassphrasePayload {

    /// Hard ceiling: 1-byte length prefix keeps L in 1...254 so the framed
    /// payload fed to `ShamirSecretSharing.split` is at most 255 bytes and
    /// `ShamirPaperFormat.encode`'s 255-byte value guard can never trip.
    public static let maxPassphraseUTF8Bytes = 254

    // MARK: - Encode

    /// Frames a passphrase as `[L][UTF-8 bytes]`.
    public static func encode(passphrase: String) throws -> Data {
        let utf8 = Data(passphrase.utf8)
        guard !utf8.isEmpty else { throw ShamirPassphrasePayloadError.empty }
        guard utf8.count <= maxPassphraseUTF8Bytes else {
            throw ShamirPassphrasePayloadError.tooLong
        }
        var payload = Data(capacity: utf8.count + 1)
        payload.append(UInt8(utf8.count))
        payload.append(utf8)
        return payload
    }

    // MARK: - Decode

    /// Decodes a framed payload back into the passphrase String, validating
    /// the framing and the UTF-8 round-trip before returning (research §1
    /// pin: a non-round-tripping reconstruction is an error, never a
    /// displayed mojibake passphrase).
    public static func decode(_ data: Data) throws -> String {
        guard !data.isEmpty else { throw ShamirPassphrasePayloadError.malformed }
        let length = Int(data[data.startIndex])
        guard length >= 1 else { throw ShamirPassphrasePayloadError.malformed }
        guard data.count == length + 1 else {
            throw ShamirPassphrasePayloadError.malformed
        }
        let utf8 = Data(data[(data.startIndex + 1)...])
        let passphrase = String(decoding: utf8, as: UTF8.self)
        guard Data(passphrase.utf8) == utf8 else {
            throw ShamirPassphrasePayloadError.notRoundTripping
        }
        return passphrase
    }
}
