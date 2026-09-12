import Foundation

/// Errors thrown by SeedQR encoding and decoding. All `Equatable` for
/// exact-case test assertions; no case carries mnemonic material.
public enum SeedQRError: Error, Equatable {
    /// Standard SeedQR digit string is not exactly 48 (12 words) or
    /// 96 (24 words) characters.
    case invalidLength
    /// A 4-digit slice contains a non-digit character.
    case invalidDigit
    /// A 4-digit slice exceeds 2047, the largest BIP39 wordlist index.
    case indexOutOfRange
    /// Compact SeedQR payload is not exactly 16 or 32 bytes.
    case invalidPayloadLength
}

/// SeedQR Standard and Compact codecs (CORE-09, D-09): pure encode/decode
/// over validated BIP39 mnemonics. QR matrix imaging itself is Phase 7
/// (RECOV-05) — this API deals in `String` (Standard) and `Data` (Compact).
///
/// **Standard SeedQR** — the 0-based wordlist index of each word, zero-padded
/// to exactly 4 decimal digits, concatenated: 48 digits for 12 words, 96 for
/// 24 (`"abandon"` → `"0000"`). Decoding slices fixed 4-digit groups, checks
/// each index against the wordlist bounds, and then runs the full BIP39
/// checksum validation (`Bip39.validate`) — a digit string only round-trips
/// if the phrase it spells is a valid mnemonic.
///
/// **Compact SeedQR** — the payload is **exactly the raw BIP39 entropy**:
/// 16 bytes for 12 words, 32 bytes for 24. This follows the official spec
/// (SeedSigner `docs/seed_qr/README.md`, the origin specification D-09
/// defers to), which corrects 02-CONTEXT.md D-09's "each word = 2 characters"
/// parenthetical: the official format has **no 2-character mapping table**.
///
/// Equivalence proof (why Compact = entropy): every BIP39 word index is one
/// 11-bit group of the ENT‖CS bit stream, so concatenating 11 bits per index
/// reproduces ENT‖CS exactly. Dropping the trailing checksum bits — CS =
/// ENT/32 of them (4 for 12 words, 8 for 24) — leaves precisely the ENT bit
/// stream, and ENT (128 or 256 bits) re-groups into the original entropy
/// bytes. The 12-word stream (132 bits) pads to 17 bytes only at the end, so
/// the first 16 bytes are ENT; the 24-word stream (264 bits) is exactly 33
/// bytes and the 33rd byte is the checksum byte. Decoding regenerates and
/// verifies the checksum via `Bip39.mnemonic(fromEntropy:)`, so a tampered
/// payload is rejected, never silently re-worded.
public enum SeedQR {

    // MARK: - Standard

    /// Encodes a valid mnemonic as its Standard SeedQR digit string
    /// (48 digits for 12 words, 96 for 24). The mnemonic is fully validated
    /// first (wordlist membership + checksum) via `Bip39.entropy`.
    public static func standardEncode(_ words: [String]) throws -> String {
        // Full BIP39 validation as a side effect of the entropy conversion.
        _ = try Bip39.entropy(fromMnemonic: words)
        var digits = ""
        digits.reserveCapacity(words.count * 4)
        for word in words {
            let index = Bip39Wordlist.englishIndices[word]!
            digits += String(index).leftPadded(toLength: 4)
        }
        return digits
    }

    /// Decodes a Standard SeedQR digit string back into a validated mnemonic.
    /// Order of checks: exact length (48/96) → digit-only 4-digit slices →
    /// index bound (≤ 2047) → BIP39 checksum via `Bip39.validate`.
    public static func standardDecode(_ digits: String) throws -> [String] {
        guard digits.count == 48 || digits.count == 96 else {
            throw SeedQRError.invalidLength
        }
        var words: [String] = []
        words.reserveCapacity(digits.count / 4)
        var index = digits.startIndex
        while index < digits.endIndex {
            let end = digits.index(index, offsetBy: 4)
            let slice = digits[index..<end]
            var value = 0
            for scalar in slice.unicodeScalars {
                // Strict ASCII decimal: fullwidth or exotic digit lookalikes
                // are rejected, not coerced.
                guard scalar.value >= 0x30, scalar.value <= 0x39 else {
                    throw SeedQRError.invalidDigit
                }
                value = value * 10 + Int(scalar.value - 0x30)
            }
            guard value <= 2047 else {
                throw SeedQRError.indexOutOfRange
            }
            words.append(Bip39Wordlist.english[value])
            index = end
        }
        try Bip39.validate(words)
        return words
    }

    // MARK: - Compact

    /// Encodes a valid mnemonic as its Compact SeedQR payload — the raw
    /// BIP39 entropy (16 bytes for 12 words, 32 for 24; see the equivalence
    /// proof in the module doc comment).
    public static func compactEncode(_ words: [String]) throws -> Data {
        try Bip39.entropy(fromMnemonic: words)
    }

    /// Decodes a Compact SeedQR payload back into a validated mnemonic.
    /// The payload must be exactly 16 or 32 bytes; the BIP39 checksum is
    /// regenerated and verified during `Bip39.mnemonic(fromEntropy:)`.
    public static func compactDecode(_ payload: Data) throws -> [String] {
        guard payload.count == 16 || payload.count == 32 else {
            throw SeedQRError.invalidPayloadLength
        }
        return try Bip39.mnemonic(fromEntropy: payload)
    }
}

private extension String {
    /// Zero-pads a decimal index on the left to exactly `length` characters.
    func leftPadded(toLength length: Int) -> String {
        guard count < length else { return self }
        return String(repeating: "0", count: length - count) + self
    }
}
