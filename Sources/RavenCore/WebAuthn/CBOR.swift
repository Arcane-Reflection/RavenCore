import Foundation

/// Minimal deterministic CBOR encoder (06-CONTEXT D-10) — just enough of
/// RFC 8949 for the WebAuthn attestation object and COSE key maps, and no
/// more: the project has zero third-party dependencies and a general-purpose
/// CBOR codec has no other consumer. Maps are emitted in canonical
/// bytewise-lexicographic key order (RFC 8949 §4.2.1 / CTAP2 canonical form),
/// which is what the attestation object's `{attStmt, authData, fmt}` and the
/// COSE key's `{1, 3, -1, -2, -3}` layouts require.
///
/// Determinism is the whole point: the same value always encodes to the same
/// bytes, and `WebAuthnTests` pins the exact byte layouts.
public enum CBOR {

    /// The value model the encoder supports. Integers use a convenience
    /// constructor so callers write `.int(-7)` instead of the RFC's
    /// `-1 - n` argument encoding.
    public enum Value: Sendable {
        case unsignedInt(UInt64)
        case negativeInt(UInt64)
        case byteString(Data)
        case text(String)
        case array([Value])
        /// Entries are encoded in canonical bytewise key order regardless of
        /// construction order — callers cannot produce a non-canonical map.
        case map([(key: Value, value: Value)])

        /// Convenience: any Swift integer (negative values use major type 1).
        public static func int(_ value: Int) -> Value {
            value >= 0
                ? .unsignedInt(UInt64(value))
                : .negativeInt(UInt64(-1 - value))
        }
    }

    /// Encodes `value` to canonical CBOR bytes.
    public static func encode(_ value: Value) -> Data {
        var output = Data()
        encode(value, into: &output)
        return output
    }

    // MARK: - Private

    private static func encode(_ value: Value, into output: inout Data) {
        switch value {
        case .unsignedInt(let n):
            encodeHead(major: 0, argument: n, into: &output)
        case .negativeInt(let argument):
            // The stored argument is already `-1 - n` (RFC 8949 §3.1).
            encodeHead(major: 1, argument: argument, into: &output)
        case .byteString(let bytes):
            encodeHead(major: 2, argument: UInt64(bytes.count), into: &output)
            output.append(bytes)
        case .text(let string):
            let bytes = Data(string.utf8)
            encodeHead(major: 3, argument: UInt64(bytes.count), into: &output)
            output.append(bytes)
        case .array(let items):
            encodeHead(major: 4, argument: UInt64(items.count), into: &output)
            for item in items {
                encode(item, into: &output)
            }
        case .map(let entries):
            encodeHead(major: 5, argument: UInt64(entries.count), into: &output)
            for entry in entries.sorted(by: { bytewiseLess(encodedKey($0.key), encodedKey($1.key)) }) {
                encode(entry.key, into: &output)
                encode(entry.value, into: &output)
            }
        }
    }

    /// Cached canonical key bytes for the bytewise sort.
    private static func encodedKey(_ key: Value) -> Data {
        encode(key)
    }

    /// Lexicographic byte comparison (Data is not Comparable).
    private static func bytewiseLess(_ lhs: Data, _ rhs: Data) -> Bool {
        for (a, b) in zip(lhs, rhs) where a != b {
            return a < b
        }
        return lhs.count < rhs.count
    }

    /// RFC 8949 §3.1 head encoding: major type in the top 3 bits, argument
    /// inline below 24, else the minimal 1/2/4/8-byte big-endian form.
    private static func encodeHead(major: UInt8, argument: UInt64, into output: inout Data) {
        let majorBits = major << 5
        switch argument {
        case 0...23:
            output.append(majorBits | UInt8(argument))
        case 0x00...0xFF:
            output.append(majorBits | 24)
            output.append(UInt8(truncatingIfNeeded: argument))
        case 0x100...0xFFFF:
            output.append(majorBits | 25)
            output.append(contentsOf: bigEndianBytes(UInt16(argument)))
        case 0x1_0000...0xFFFF_FFFF:
            output.append(majorBits | 26)
            output.append(contentsOf: bigEndianBytes(UInt32(argument)))
        default:
            output.append(majorBits | 27)
            output.append(contentsOf: bigEndianBytes(argument))
        }
    }

    /// Big-endian byte form of a fixed-width integer.
    private static func bigEndianBytes<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }
}
