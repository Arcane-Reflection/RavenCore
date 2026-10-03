import Foundation

/// RFC 4648 Base32 codec (06-CONTEXT D-06/D-07) — the one hand-written TOTP
/// primitive; every other step rides CryptoKit. Decode covers the stored
/// secret paths; encode (06-03) composes `otpauth://` URIs for CXF imports
/// whose secrets arrive as raw bytes (D-11).
///
/// Tolerance decisions (each pinned by `Base32Tests`):
/// - Case-insensitive — lowercase input normalizes to the RFC alphabet.
/// - Trailing padding (`=`) is tolerated and stripped on read; padding is
///   never required (Google Authenticator-style secrets are unpadded).
/// - Non-canonical (non-zero) leftover bits are tolerated — sloppy
///   generators exist and the import paths feed this decoder.
/// - Anything outside the RFC 4648 alphabet (including whitespace and the
///   digits 0/1/8/9) is a typed error, as is `=` anywhere but the end —
///   fail-closed (RESEARCH security domain V5).
/// - Unpadded lengths that cannot encode whole bytes (≡ 1, 3 or 6 mod 8)
///   are a typed error.
public enum Base32 {

    public enum Base32Error: Error, Equatable {
        /// A character outside the RFC 4648 alphabet (or padding not at the end).
        case invalidCharacter
        /// The unpadded length cannot encode a whole number of bytes
        /// (character count ≡ 1, 3 or 6 mod 8).
        case invalidLength
    }

    private static let alphabet: [Character] =
        Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    private static let valueOf: [Character: UInt8] = Dictionary(
        uniqueKeysWithValues: alphabet.enumerated().map { ($1, UInt8($0)) })

    /// Decodes `string` into the bytes it encodes. Empty input decodes to
    /// an empty array.
    public static func decode(_ string: String) throws -> [UInt8] {
        var input = Substring(string.uppercased())
        while input.last == "=" {
            input = input.dropLast()
        }
        var values: [UInt8] = []
        values.reserveCapacity(input.count)
        for character in input {
            guard let value = valueOf[character] else {
                throw Base32Error.invalidCharacter
            }
            values.append(value)
        }
        switch values.count % 8 {
        case 1, 3, 6:
            throw Base32Error.invalidLength
        default:
            break
        }
        var output: [UInt8] = []
        var buffer = 0
        var bits = 0
        for value in values {
            buffer = ((buffer << 5) | Int(value)) & 0xFFFF
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((buffer >> bits) & 0xFF))
            }
        }
        return output
    }

    /// Encodes `bytes` in the canonical otpauth form: uppercase RFC 4648
    /// alphabet, NO padding (the Google Authenticator URI convention — the
    /// decoder tolerates both spellings). Empty input encodes to an empty
    /// string.
    public static func encode(_ bytes: [UInt8]) -> String {
        var output = ""
        output.reserveCapacity((bytes.count * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for byte in bytes {
            buffer = ((buffer << 8) | Int(byte)) & 0xFFFFF
            bits += 8
            while bits >= 5 {
                bits -= 5
                output.append(alphabet[(buffer >> bits) & 0x1F])
            }
        }
        if bits > 0 {
            // Flush the final partial chunk — non-zero leftover bits are the
            // same tolerance the decode side accepts.
            output.append(alphabet[(buffer << (5 - bits)) & 0x1F])
        }
        return output
    }
}
