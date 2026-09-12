import Foundation

/// Cursor-based little-endian binary reader over a `Data` buffer.
///
/// KDBX stores every multi-byte integer little-endian (keepass.info spec);
/// never rely on native memory order. All out-of-bounds access throws
/// `KdbxError.malformedData` instead of crashing.
public struct ByteReader {
    /// The buffer being read.
    public let data: Data
    /// Current read cursor (0-based byte offset).
    public var offset: Int

    /// Creates a reader positioned at the start of `data`.
    public init(_ data: Data) {
        self.data = data
        self.offset = 0
    }

    /// Bytes left between the cursor and the end of the buffer.
    public var remaining: Int { data.count - offset }
    /// `true` when no bytes remain.
    public var isAtEnd: Bool { remaining <= 0 }

    /// Reads `count` bytes and advances the cursor; throws on underflow.
    public mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0, count <= remaining else { throw KdbxError.malformedData }
        defer { offset += count }
        return data.subdata(in: (data.startIndex + offset) ..< (data.startIndex + offset + count))
    }

    /// Reads one unsigned byte.
    public mutating func readUInt8() throws -> UInt8 {
        try readBytes(1).first ?? 0
    }

    /// Reads one little-endian UInt16.
    public mutating func readUInt16() throws -> UInt16 {
        let raw = try readBytes(2)
        return UInt16(raw[raw.startIndex]) | (UInt16(raw[raw.startIndex + 1]) << 8)
    }

    /// Reads one little-endian UInt32.
    public mutating func readUInt32() throws -> UInt32 {
        let raw = try readBytes(4)
        var v: UInt32 = 0
        for (i, b) in raw.enumerated() { v |= UInt32(b) << (8 * i) }
        return v
    }

    /// Reads one little-endian UInt64.
    public mutating func readUInt64() throws -> UInt64 {
        let raw = try readBytes(8)
        var v: UInt64 = 0
        for (i, b) in raw.enumerated() { v |= UInt64(b) << (8 * i) }
        return v
    }

    /// Reads one little-endian Int32 (two’s-complement of the UInt32 read).
    public mutating func readInt32() throws -> Int32 {
        Int32(bitPattern: try readUInt32())
    }
}

/// Little-endian binary writer.
public struct ByteWriter {
    /// Bytes written so far.
    public private(set) var data: Data

    /// Creates an empty writer.
    public init() {
        data = Data()
    }

    /// Appends raw bytes.
    public mutating func writeBytes(_ bytes: Data) {
        data.append(bytes)
    }

    /// Appends one unsigned byte.
    public mutating func writeUInt8(_ v: UInt8) {
        data.append(v)
    }

    /// Appends one little-endian UInt16.
    public mutating func writeUInt16(_ v: UInt16) {
        data.append(UInt8(v & 0xFF))
        data.append(UInt8((v >> 8) & 0xFF))
    }

    /// Appends one little-endian UInt32.
    public mutating func writeUInt32(_ v: UInt32) {
        for i in 0..<4 { data.append(UInt8((v >> (8 * i)) & 0xFF)) }
    }

    /// Appends one little-endian UInt64.
    public mutating func writeUInt64(_ v: UInt64) {
        for i in 0..<8 { data.append(UInt8((v >> (8 * i)) & 0xFF)) }
    }

    /// Appends one little-endian Int32.
    public mutating func writeInt32(_ v: Int32) {
        writeUInt32(UInt32(bitPattern: v))
    }
}
