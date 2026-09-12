import Foundation

/// Errors thrown by the Shamir paper format. All `Equatable` for exact-case
/// test assertions, mirroring the engine's per-module error enum convention.
/// No case carries secret payload values (T-01-02 convention).
public enum ShamirPaperFormatError: Error, Equatable {
    /// A character outside the Crockford alphabet (including `U`, which is
    /// reserved for the mod-37 checksum we deliberately do not use).
    case invalidCharacter
    /// Input is empty or too short to carry header + checksum + value.
    case unexpectedEnd
    /// CRC-32 over the decoded byte string does not match its trailing
    /// checksum — the share was mis-transcribed (checked BEFORE any header
    /// interpretation, and never fed into `combine`).
    case checksumMismatch
    /// Wire version byte differs from v1 (`payload` = the unknown version).
    case versionUnsupported(UInt8)
    /// Shares in one recovery attempt disagree on version/threshold/total,
    /// or a decoded header is internally inconsistent.
    case inconsistentHeaders
    /// Two paper shares carry the same Shamir index.
    case duplicateShareIndex
    /// Fewer distinct shares than the (self-described) threshold.
    case insufficientShares
    /// Encode arguments violate the Shamir parameter bounds.
    case invalidConfiguration
}

/// A decoded paper share: the Shamir share itself plus the self-describing
/// header values (any-3-of-5 is printed on the paper, D-05).
public struct ShamirPaperShare: Sendable, Equatable {
    /// The recovered share.
    public let share: ShamirShare
    /// Threshold printed on the share (self-describing recovery, D-05).
    public let threshold: UInt8
    /// Total shares printed on the share.
    public let totalShares: UInt8
    /// Paper-format version byte (one-way versioning, D-04).
    public let version: UInt8

    /// Creates a decoded paper share.
    public init(share: ShamirShare, threshold: UInt8, totalShares: UInt8, version: UInt8) {
        self.share = share
        self.threshold = threshold
        self.totalShares = totalShares
        self.version = version
    }
}

/// Printable, checksum-protected encoding of Shamir shares for paper recovery
/// cards (CORE-08). Pure codec layer above `ShamirSecretSharing` — the GF(2^8)
/// math is untouched (D-04).
///
/// Wire layout v1 (per share, before text encoding):
///
///     [0]         version      = 0x01
///     [1]         threshold    = k   (2...255)
///     [2]         total shares = n   (k ≤ n ≤ 255)
///     [3]         share index  = 1...255 (ShamirShare.index)
///     [4]         value length = L   (1...255 bytes)
///     [5..4+L]    share value  = ShamirShare.value
///     [5+L..8+L]  CRC-32/ISO-HDLC over bytes [0 .. 4+L], big-endian
///
/// Encoded byte count B = 9 + L; text width = ceil(8·B/5) Crockford Base32
/// characters (MSB-first bit stream, last group zero-padded on the right,
/// left-padded with `0` to the fixed width), presented in 5-character groups
/// separated by `-`. Decoding accepts any `-`/whitespace layout (spec §3
/// anticipates line-wrapped cards), verifies the CRC **before** interpreting
/// the header, and never hands a corrupt share to
/// `ShamirSecretSharing.combine` (T-01-03: a mis-copied share must fail
/// loudly, not reconstruct silently).
public enum ShamirPaperFormat {

    /// v1 wire version — the only evolution path is a new version byte (D-04,
    /// additive-only public contract).
    public static let versionByte: UInt8 = 0x01

    static let headerByteCount = 5
    static let checksumByteCount = 4

    // MARK: - Encode

    /// Encodes one share into its printable paper form.
    public static func encode(share: ShamirShare, threshold: UInt8, totalShares: UInt8) throws -> String {
        guard threshold >= 2,
              totalShares >= threshold,
              share.index >= 1,
              !share.value.isEmpty,
              share.value.count <= 255
        else {
            throw ShamirPaperFormatError.invalidConfiguration
        }

        var bytes = Data(capacity: headerByteCount + share.value.count + checksumByteCount)
        bytes.append(versionByte)
        bytes.append(threshold)
        bytes.append(totalShares)
        bytes.append(share.index)
        bytes.append(UInt8(share.value.count))
        bytes.append(share.value)
        appendBigEndian(CRC32.checksum(bytes), to: &bytes)

        // B = 9 + L; width = ceil(8·B/5) — every share of a given secret
        // prints at identical width.
        let width = (8 * bytes.count + 4) / 5
        return present(CrockfordBase32.encode(bytes, width: width))
    }

    // MARK: - Decode

    /// Decodes one paper share. Order is normative: normalize → character
    /// validation → bit-stream reassembly → **CRC verify** → header
    /// interpretation. A CRC failure is always `checksumMismatch`, never a
    /// downstream parse error.
    public static func decode(_ paper: String) throws -> ShamirPaperShare {
        let raw = try CrockfordBase32.decode(normalized(paper))
        guard raw.count >= headerByteCount + checksumByteCount + 1 else {
            throw ShamirPaperFormatError.unexpectedEnd
        }

        let payloadEnd = raw.count - checksumByteCount
        let payload = Data(raw[0..<payloadEnd])
        var stored: UInt32 = 0
        for byte in raw[payloadEnd...] {
            stored = (stored << 8) | UInt32(byte)
        }
        guard CRC32.checksum(payload) == stored else {
            throw ShamirPaperFormatError.checksumMismatch
        }

        let version = raw[0]
        guard version == versionByte else {
            throw ShamirPaperFormatError.versionUnsupported(version)
        }
        let threshold = raw[1]
        let totalShares = raw[2]
        let index = raw[3]
        let valueLength = raw[4]
        guard threshold >= 2,
              totalShares >= threshold,
              index >= 1,
              valueLength == raw.count - headerByteCount - checksumByteCount
        else {
            throw ShamirPaperFormatError.inconsistentHeaders
        }

        return ShamirPaperShare(
            share: ShamirShare(
                index: index,
                value: Data(raw[headerByteCount..<(headerByteCount + Int(valueLength))])
            ),
            threshold: threshold,
            totalShares: totalShares,
            version: version
        )
    }

    // MARK: - Recover

    /// Reconstructs the secret from paper shares only. Enforces, in order:
    /// per-share decode (CRC first) → consistent version/threshold/total →
    /// distinct indices → enough shares → `ShamirSecretSharing.combine`.
    public static func recover(fromPaper papers: [String]) throws -> Data {
        guard !papers.isEmpty else { throw ShamirPaperFormatError.insufficientShares }

        var shares: [ShamirShare] = []
        var threshold: UInt8?
        var totalShares: UInt8?
        var version: UInt8?

        for paper in papers {
            let decoded = try decode(paper)
            if let knownThreshold = threshold, let knownTotal = totalShares, let knownVersion = version {
                guard decoded.threshold == knownThreshold,
                      decoded.totalShares == knownTotal,
                      decoded.version == knownVersion
                else {
                    throw ShamirPaperFormatError.inconsistentHeaders
                }
            } else {
                threshold = decoded.threshold
                totalShares = decoded.totalShares
                version = decoded.version
            }
            shares.append(decoded.share)
        }

        guard let k = threshold else { throw ShamirPaperFormatError.unexpectedEnd }
        guard Set(shares.map(\.index)).count == shares.count else {
            throw ShamirPaperFormatError.duplicateShareIndex
        }
        guard shares.count >= Int(k) else { throw ShamirPaperFormatError.insufficientShares }

        return try ShamirSecretSharing.combine(shares: shares, threshold: Int(k))
    }

    // MARK: - Presentation

    /// Strips `-` group separators and all whitespace before decoding
    /// (spec §3/§5 step 1: cards may wrap lines every 4–5 groups, so a
    /// consumed share carries spaces/newlines — "all whitespace and hyphens
    /// are stripped before decoding").
    static func normalized(_ paper: String) -> String {
        paper.filter { $0 != "-" && !$0.isWhitespace }
    }

    /// 5-character groups separated by `-` (last group may be short).
    static func present(_ encoded: String) -> String {
        var groups: [String] = []
        var index = encoded.startIndex
        while index < encoded.endIndex {
            let end = encoded.index(index, offsetBy: 5, limitedBy: encoded.endIndex) ?? encoded.endIndex
            groups.append(String(encoded[index..<end]))
            index = end
        }
        return groups.joined(separator: "-")
    }

    private static func appendBigEndian(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }
}

/// Crockford Base32 (crockford.com/base32.html, 2019) over byte strings:
/// MSB-first bit stream, 5 bits per character, final group zero-padded on the
/// right, left-padded with `0` to a caller-fixed width. Encode emits uppercase
/// only from the 32-symbol alphabet that excludes I, L, O, U. Decode is
/// case-insensitive, aliases I/i/L/l → 1 and O/o → 0, ignores `-`, rejects
/// `U` (reserved for the mod-37 checksum we do not use), and rejects every
/// other foreign symbol.
enum CrockfordBase32 {

    static let alphabet: [Character] = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    private static let encodeTable: [Character] = alphabet

    private static let decodeTable: [Character: Int] = {
        var table: [Character: Int] = [:]
        for (index, character) in alphabet.enumerated() {
            table[character] = index
        }
        // Human-transcription aliases (resolved on uppercased input).
        table["I"] = 1
        table["L"] = 1
        table["O"] = 0
        return table
    }()

    /// Encodes `data` into exactly `width` characters (left-padded with `0`).
    static func encode(_ data: Data, width: Int) -> String {
        var characters: [Character] = []
        characters.reserveCapacity(width)
        var bitBuffer = 0
        var bitCount = 0
        for byte in data {
            bitBuffer = (bitBuffer << 8) | Int(byte)
            bitCount += 8
            while bitCount >= 5 {
                bitCount -= 5
                characters.append(encodeTable[(bitBuffer >> bitCount) & 31])
            }
        }
        if bitCount > 0 {
            // Final partial group: pad the low bits with zeros.
            characters.append(encodeTable[(bitBuffer << (5 - bitCount)) & 31])
        }
        if characters.count < width {
            characters.insert(contentsOf: Array(repeating: "0", count: width - characters.count), at: 0)
        }
        return String(characters)
    }

    /// Decodes a separator-free Crockford string back into bytes. Decoding is
    /// case-insensitive with the Crockford aliases (I/L → 1, O → 0). The
    /// trailing partial group's padding bits are discarded — but they must be
    /// zero: a string whose padding bits are set is not the canonical encoding
    /// of any byte string and is rejected as mis-transcribed, so *every*
    /// single-symbol substitution in a printed share fails verification.
    static func decode(_ compact: String) throws -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(compact.count * 5 / 8)
        var bitBuffer = 0
        var bitCount = 0
        for character in compact {
            if character == "-" { continue }
            guard let value = value(of: character) else {
                throw ShamirPaperFormatError.invalidCharacter
            }
            bitBuffer = (bitBuffer << 5) | value
            bitCount += 5
            if bitCount >= 8 {
                bitCount -= 8
                bytes.append(UInt8((bitBuffer >> bitCount) & 0xFF))
            }
        }
        if bitCount > 0, bitBuffer & ((1 << bitCount) - 1) != 0 {
            throw ShamirPaperFormatError.checksumMismatch
        }
        return bytes
    }

    /// Case-insensitive lookup; `U`/`u` and every foreign symbol are absent
    /// from the table and surface as `invalidCharacter`.
    private static func value(of character: Character) -> Int? {
        decodeTable[Character(String(character).uppercased())]
    }
}
