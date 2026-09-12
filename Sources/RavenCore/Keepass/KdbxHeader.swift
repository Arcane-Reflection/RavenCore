import Foundation

/// KDBX 4 outer header (keepass.info 4.1 spec §"Header").
///
/// Wire layout: signature (2×UInt32) ‖ version (UInt32) ‖ fields
/// (`t:UInt8 ‖ len:Int32-LE ‖ V`) terminated by field 0, then a raw
/// `SHA-256(header)` (32B) and `HMAC-SHA-256(header)` (32B).
/// Legacy fields 1/5/6/8/9/10 are skipped but retained (D-06 opaque).
public struct KdbxOuterHeader: Sendable, Equatable {
    /// Payload compression flags (spec CompressionFlags).
    public enum Compression: Int32, Sendable, Equatable {
        case none = 0
        case gzip = 1
    }

    /// Header field IDs valid in KDBX 4.
    public enum FieldID: UInt8 {
        case endOfHeader = 0
        case cipherID = 2
        case compressionFlags = 3
        case masterSeed = 4
        case encryptionIV = 7
        case kdfParameters = 11
        case publicCustomData = 12
    }

    /// File signature constants.
    public static let signature1: UInt32 = 0x9AA2_D903
    /// Second signature word (0xB54BFB67).
    public static let signature2: UInt32 = 0xB54B_FB67
    /// Version critical mask — the high 16 bits must not exceed 4.
    public static let versionCriticalMask: UInt32 = 0xFFFF_0000
    /// Exact 4.0 version constant.
    public static let version40: UInt32 = 0x0004_0000
    /// Exact 4.1 version constant.
    public static let version41: UInt32 = 0x0004_0001
    /// Exact 3.1 version constant (read-only).
    public static let version31: UInt32 = 0x0003_0001

    /// Packed version word (major in the high 16 bits).
    public var version: UInt32
    /// Outer cipher UUID.
    public var cipherId: UUID
    /// Payload compression.
    public var compression: Compression
    /// 32-byte master seed for the key schedule.
    public var masterSeed: Data
    /// Outer cipher IV.
    public var encryptionIV: Data
    /// KDF parameters (field 11 variant dictionary).
    public var kdfParameters: VariantDictionary
    /// Plugin data carried in the header, if present.
    public var publicCustomData: VariantDictionary?
    /// Legacy/unrecognized fields (ID + raw value), replayed on write.
    public var unknownFields: [OpaqueField]

    /// The raw header bytes (signature through end-of-header field) — needed
    /// for the SHA-256 and HMAC values that follow.
    public private(set) var rawBytes: Data

    /// 32-byte SHA-256 of `rawBytes` (pre-master-key integrity check).
    public var hash: Data { Hmac.sha256(rawBytes) }

    /// Parses signature, version, and fields up to the end-of-header marker.
    public static func read(_ data: Data) throws -> KdbxOuterHeader {
        guard data.count >= 12 else { throw KdbxError.corruptFile }
        var reader = ByteReader(data)
        let sig1 = try reader.readUInt32()
        let sig2 = try reader.readUInt32()
        guard sig1 == Self.signature1, sig2 == Self.signature2 else {
            throw KdbxError.corruptFile
        }
        let version = try reader.readUInt32()
        guard version & Self.versionCriticalMask <= Self.version40 & Self.versionCriticalMask else {
            throw KdbxError.unsupportedVersion(version)
        }

        var header = KdbxOuterHeader(
            version: version,
            cipherId: KdbxCrypto.aesCipherUUID,
            compression: .gzip,
            masterSeed: Data(),
            encryptionIV: Data(),
            kdfParameters: VariantDictionary(),
            publicCustomData: nil,
            unknownFields: [OpaqueField](),
            rawBytes: Data()
        )

        var raw = ByteWriter()
        raw.writeUInt32(sig1)
        raw.writeUInt32(sig2)
        raw.writeUInt32(version)

        var sawEnd = false
        while !sawEnd {
            let id = try reader.readUInt8()
            let length = Int(try reader.readInt32())
            guard length >= 0, length <= reader.remaining else { throw KdbxError.corruptFile }
            let value = try reader.readBytes(length)
            raw.writeUInt8(id)
            raw.writeInt32(Int32(length))
            raw.writeBytes(value)

            switch id {
            case FieldID.endOfHeader.rawValue:
                sawEnd = true
            case FieldID.cipherID.rawValue:
                guard let uuid = UUID(data: value) else { throw KdbxError.corruptFile }
                header.cipherId = uuid
            case FieldID.compressionFlags.rawValue:
                var valueReader = ByteReader(value)
                guard let compression = Compression(rawValue: try valueReader.readInt32()) else {
                    throw KdbxError.malformedData
                }
                header.compression = compression
            case FieldID.masterSeed.rawValue:
                header.masterSeed = value
            case FieldID.encryptionIV.rawValue:
                header.encryptionIV = value
            case FieldID.kdfParameters.rawValue:
                header.kdfParameters = try VariantDictionary(data: value)
            case FieldID.publicCustomData.rawValue:
                header.publicCustomData = try VariantDictionary(data: value)
            default:
                // Legacy (1/5/6/8/9/10) or unrecognized plugin fields.
                header.unknownFields.append(OpaqueField(id: id, value: value))
            }
        }
        header.rawBytes = raw.data
        return header
    }

    /// Serializes signature + version + fields (no trailing hash/HMAC).
    public func serialize() -> Data {
        var raw = ByteWriter()
        raw.writeUInt32(Self.signature1)
        raw.writeUInt32(Self.signature2)
        raw.writeUInt32(version)
        raw.writeUInt8(FieldID.cipherID.rawValue)
        raw.writeInt32(16)
        raw.writeBytes(cipherId.data)
        var flags = ByteWriter()
        flags.writeInt32(compression.rawValue)
        writeField(&raw, id: FieldID.compressionFlags.rawValue, value: flags.data)
        writeField(&raw, id: FieldID.masterSeed.rawValue, value: masterSeed)
        writeField(&raw, id: FieldID.encryptionIV.rawValue, value: encryptionIV)
        writeField(&raw, id: FieldID.kdfParameters.rawValue, value: kdfParameters.serialize())
        if let publicCustomData {
            writeField(&raw, id: FieldID.publicCustomData.rawValue, value: publicCustomData.serialize())
        }
        for field in unknownFields {
            writeField(&raw, id: field.id, value: field.value)
        }
        // Spec (§3.1): the EndOfHeader value MUST be exactly 0D 0A 0D 0A.
        writeField(&raw, id: FieldID.endOfHeader.rawValue, value: Data([0x0D, 0x0A, 0x0D, 0x0A]))
        return raw.data
    }

    private func writeField(_ writer: inout ByteWriter, id: UInt8, value: Data) {
        writer.writeUInt8(id)
        writer.writeInt32(Int32(value.count))
        writer.writeBytes(value)
    }

    /// `rawBytes` is a parse artifact (original wire bytes), not semantic
    /// content — equality compares the parsed fields only.
    public static func == (lhs: KdbxOuterHeader, rhs: KdbxOuterHeader) -> Bool {
        lhs.version == rhs.version
            && lhs.cipherId == rhs.cipherId
            && lhs.compression == rhs.compression
            && lhs.masterSeed == rhs.masterSeed
            && lhs.encryptionIV == rhs.encryptionIV
            && lhs.kdfParameters == rhs.kdfParameters
            && lhs.publicCustomData == rhs.publicCustomData
            && lhs.unknownFields == rhs.unknownFields
    }
}

/// Header authentication values that follow the raw header.
public enum KdbxHeaderAuthentication {
    /// Reads and verifies the trailing `SHA-256(header)` + `HMAC-SHA-256(header)`.
    public static func verify(data: Data, headerByteCount: Int, headerHmacKey: Data) throws {
        var reader = ByteReader(data)
        reader.offset = headerByteCount
        guard reader.remaining >= 64 else { throw KdbxError.corruptFile }
        let storedHash = try reader.readBytes(32)
        let storedHmac = try reader.readBytes(32)
        let headerBytes = data.subdata(in: data.startIndex ..< data.startIndex + headerByteCount)
        guard Hmac.constantTimeEquals(Hmac.sha256(headerBytes), storedHash) else {
            throw KdbxError.corruptFile
        }
        guard Hmac.constantTimeEquals(Hmac.hmacSHA256(key: headerHmacKey, message: headerBytes), storedHmac) else {
            // Authenticity failure — wrong credentials or tampering (uniform).
            throw KdbxError.wrongCredentials
        }
    }

    /// Produces the trailing hash + HMAC for `headerBytes`.
    public static func serialize(headerBytes: Data, headerHmacKey: Data) -> Data {
        Hmac.sha256(headerBytes) + Hmac.hmacSHA256(key: headerHmacKey, message: headerBytes)
    }
}
