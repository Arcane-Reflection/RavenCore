import Foundation

/// KDBX variant dictionary (keepass.info 4.1 spec §"Variant Dictionary").
///
/// Wire format: `UInt16-LE 0x0100` version ‖ items ‖ `0x00` terminator, where
/// each item is `type:UInt8 ‖ keyLen:Int32-LE ‖ key:UTF-8 ‖ valueLen:Int32-LE ‖ value`.
/// Unknown item types are skipped but retained so plugin data survives a
/// read→write round trip (CONTEXT.md D-06 opaque preservation).
public struct VariantDictionary: Sendable, Equatable {
    /// Value type tags from the spec.
    public enum ValueType: UInt8, Sendable {
        case uint32 = 0x04
        case uint64 = 0x05
        case bool = 0x08
        case int32 = 0x0C
        case int64 = 0x0D
        case string = 0x18
        case byteArray = 0x42
    }

    /// A typed variant value (spec type tags).
    public enum Value: Sendable, Equatable {
        case uint32(UInt32)
        case uint64(UInt64)
        case bool(Bool)
        case int32(Int32)
        case int64(Int64)
        case string(String)
        case byteArray(Data)

        var typeTag: ValueType {
            switch self {
            case .uint32: return .uint32
            case .uint64: return .uint64
            case .bool: return .bool
            case .int32: return .int32
            case .int64: return .int64
            case .string: return .string
            case .byteArray: return .byteArray
            }
        }
    }

    static let currentVersion: UInt16 = 0x0100

    private var storage: [String: Value] = [:]
    /// Items whose type tag was unknown at read time, preserved verbatim.
    private var opaqueItems: [OpaqueVariantItem] = []

    /// Creates an empty dictionary.
    public init() {}

    /// Parses a serialized variant dictionary (version-gated).
    public init(data: Data) throws {
        var reader = ByteReader(data)
        let version = try reader.readUInt16()
        // High byte (major) is critical; low byte (minor) informational.
        guard version & 0xFF00 == Self.currentVersion & 0xFF00 else {
            throw KdbxError.malformedData
        }
        while true {
            let tag = try reader.readUInt8()
            if tag == 0x00 { return } // terminator
            let keyLength = Int(try reader.readInt32())
            guard keyLength > 0, keyLength <= reader.remaining else { throw KdbxError.malformedData }
            let keyData = try reader.readBytes(keyLength)
            guard let key = String(data: keyData, encoding: .utf8) else { throw KdbxError.malformedData }
            let valueLength = Int(try reader.readInt32())
            guard valueLength >= 0, valueLength <= reader.remaining else { throw KdbxError.malformedData }
            let valueData = try reader.readBytes(valueLength)

            guard let type = ValueType(rawValue: tag) else {
                opaqueItems.append(OpaqueVariantItem(tag: tag, key: key, value: valueData))
                continue
            }
            storage[key] = try Self.decode(type: type, data: valueData)
        }
    }

    private static func decode(type: ValueType, data: Data) throws -> Value {
        var reader = ByteReader(data)
        // Oversized value widths are tolerated BY DECISION (02-REVIEW-FULL
        // FI-09): a bool/uint32 item carrying extra trailing bytes parses the
        // prefix where KeePassXC is strict — a read-only interop leniency,
        // since round-trip re-serializes the exact width. Truncated values
        // still fail: ByteReader bounds-checks every read.
        switch type {
        case .uint32: return .uint32(try reader.readUInt32())
        case .uint64: return .uint64(try reader.readUInt64())
        case .bool: return .bool(try reader.readUInt8() == 1)
        case .int32: return .int32(try reader.readInt32())
        case .int64: return .int64(Int64(bitPattern: try reader.readUInt64()))
        case .string:
            guard let s = String(data: data, encoding: .utf8) else { throw KdbxError.malformedData }
            return .string(s)
        case .byteArray: return .byteArray(data)
        }
    }

    /// Serializes known items (sorted by key) then opaque items, terminated.
    public func serialize() -> Data {
        var writer = ByteWriter()
        writer.writeUInt16(Self.currentVersion)
        for (key, value) in storage.sorted(by: { $0.key < $1.key }) {
            let keyData = Data(key.utf8)
            let valueData = Self.encode(value)
            writer.writeUInt8(value.typeTag.rawValue)
            writer.writeInt32(Int32(keyData.count))
            writer.writeBytes(keyData)
            writer.writeInt32(Int32(valueData.count))
            writer.writeBytes(valueData)
        }
        for item in opaqueItems {
            writer.writeUInt8(item.tag)
            writer.writeInt32(Int32(item.key.utf8.count))
            writer.writeBytes(Data(item.key.utf8))
            writer.writeInt32(Int32(item.value.count))
            writer.writeBytes(item.value)
        }
        writer.writeUInt8(0x00)
        return writer.data
    }

    private static func encode(_ value: Value) -> Data {
        var writer = ByteWriter()
        switch value {
        case .uint32(let v): writer.writeUInt32(v)
        case .uint64(let v): writer.writeUInt64(v)
        case .bool(let v): writer.writeUInt8(v ? 1 : 0)
        case .int32(let v): writer.writeInt32(v)
        case .int64(let v): writer.writeUInt64(UInt64(bitPattern: v))
        case .string(let v): writer.writeBytes(Data(v.utf8))
        case .byteArray(let v): writer.writeBytes(v)
        }
        return writer.data
    }

    // MARK: - Typed accessors

    /// Typed subscript for reading and writing.
    public subscript(key: String) -> Value? {
        get { storage[key] }
        set { storage[key] = newValue }
    }

    /// The `key`’s UInt32 value, if present with that type.
    public func uint32(_ key: String) -> UInt32? {
        if case .uint32(let v)? = storage[key] { return v }
        return nil
    }

    /// The `key`’s UInt64 value, if present with that type.
    public func uint64(_ key: String) -> UInt64? {
        if case .uint64(let v)? = storage[key] { return v }
        return nil
    }

    /// The `key`’s byte-array value, if present with that type.
    public func byteArray(_ key: String) -> Data? {
        if case .byteArray(let v)? = storage[key] { return v }
        return nil
    }

    func withOpaqueItems(_ other: [OpaqueVariantItem]) -> VariantDictionary {
        var copy = self
        copy.opaqueItems = other
        return copy
    }

    /// Unknown-type items preserved from the last parse (D-06).
    public var unknownItems: [OpaqueVariantItem] { opaqueItems }
}

/// An item with an unrecognized type tag, preserved verbatim (D-06).
public struct OpaqueVariantItem: Sendable, Equatable {
    /// Unknown type tag as it appeared on the wire.
    public let tag: UInt8
    /// Item key.
    public let key: String
    /// Raw item value.
    public let value: Data
}
