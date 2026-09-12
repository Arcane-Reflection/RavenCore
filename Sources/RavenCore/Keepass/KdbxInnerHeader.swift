import Foundation

/// KDBX 4 inner header — inside the decrypted, decompressed payload
/// (keepass.info 4.1 spec §"Inner Header"). Carries the value-protection
/// stream parameters and attachment binaries (D-07 limits enforced here).
public struct KdbxInnerHeader: Sendable, Equatable {
    /// Inner header field IDs valid in KDBX 4.
    public enum FieldID: UInt8 {
        case end = 0
        case innerRandomStreamID = 1
        case innerRandomStreamKey = 2
        case binary = 3
    }

    /// Value-protection stream algorithms: 2 = Salsa20 (KDBX 3.1), 3 = ChaCha20 (4.x default).
    public enum InnerStreamID: Int32, Sendable, Equatable {
        case arcFourVariant = 1
        case salsa20 = 2
        case chacha20 = 3
    }

    /// An attachment binary: flags byte ‖ content (flag 0x01 = protect in memory).
    public struct Binary: Sendable, Equatable {
        /// Protection flag byte (0x01 = protect the value in memory).
        public var flags: UInt8
        /// Raw attachment bytes.
        public var content: Data

        /// Creates an attachment binary.
        public init(flags: UInt8, content: Data) {
            self.flags = flags
            self.content = content
        }

        /// `true` when the protection flag bit is set.
        public var isProtected: Bool { flags & 0x01 != 0 }
    }

    /// Inner stream protecting values inside the XML.
    public var innerStreamId: InnerStreamID
    /// Key material for the inner stream (32 bytes for Salsa20, 64 for ChaCha20).
    public var innerStreamKey: Data
    /// Attachment pool; entries reference these by 0-based index.
    public var binaries: [Binary]
    /// Unrecognized inner header fields, replayed on write (D-06).
    public var unknownFields: [OpaqueField]

    /// Creates an inner header.
    public init(
        innerStreamId: InnerStreamID = .chacha20,
        innerStreamKey: Data = Data(),
        binaries: [Binary] = [],
        unknownFields: [OpaqueField] = []
    ) {
        self.innerStreamId = innerStreamId
        self.innerStreamKey = innerStreamKey
        self.binaries = binaries
        self.unknownFields = unknownFields
    }

    /// Parses the inner header, returning it together with the exact number
    /// of bytes consumed (the XML document starts immediately after).
    public static func read(_ data: Data) throws -> (header: KdbxInnerHeader, byteCount: Int) {
        var reader = ByteReader(data)
        let startOffset = reader.offset
        var header = KdbxInnerHeader()
        while true {
            let id = try reader.readUInt8()
            let length = Int(try reader.readInt32())
            guard length >= 0 else { throw KdbxError.corruptFile }
            // D-07 (threat T-03-01): enforce the attachment limit BEFORE any
            // allocation — a crafted huge binary must never be materialized.
            if id == FieldID.binary.rawValue, length - 1 > KdbxAttachments.sizeLimitBytes {
                throw KdbxError.attachmentTooLarge(limitBytes: KdbxAttachments.sizeLimitBytes)
            }
            guard length <= reader.remaining else { throw KdbxError.corruptFile }
            let value = try reader.readBytes(length)
            switch id {
            case FieldID.end.rawValue:
                return (header, reader.offset - startOffset)
            case FieldID.innerRandomStreamID.rawValue:
                var valueReader = ByteReader(value)
                guard let streamId = InnerStreamID(rawValue: try valueReader.readInt32()) else {
                    throw KdbxError.unsupportedCipher
                }
                header.innerStreamId = streamId
            case FieldID.innerRandomStreamKey.rawValue:
                header.innerStreamKey = value
            case FieldID.binary.rawValue:
                guard let flags = value.first else { throw KdbxError.malformedData }
                let content = value.subdata(in: value.startIndex + 1 ..< value.endIndex)
                header.binaries.append(Binary(flags: flags, content: content))
            default:
                header.unknownFields.append(OpaqueField(id: id, value: value))
            }
        }
    }

    /// Serializes the fields (terminated by an empty end-of-header field).
    public func serialize() -> Data {
        var writer = ByteWriter()
        var idWriter = ByteWriter()
        idWriter.writeInt32(innerStreamId.rawValue)
        writeField(&writer, id: FieldID.innerRandomStreamID.rawValue, value: idWriter.data)
        writeField(&writer, id: FieldID.innerRandomStreamKey.rawValue, value: innerStreamKey)
        for binary in binaries {
            writeField(&writer, id: FieldID.binary.rawValue, value: Data([binary.flags]) + binary.content)
        }
        for field in unknownFields {
            writeField(&writer, id: field.id, value: field.value)
        }
        writeField(&writer, id: FieldID.end.rawValue, value: Data())
        return writer.data
    }

    private func writeField(_ writer: inout ByteWriter, id: UInt8, value: Data) {
        writer.writeUInt8(id)
        writer.writeInt32(Int32(value.count))
        writer.writeBytes(value)
    }
}

/// Attachment size policy (CONTEXT.md D-07): in-memory processing with a hard
/// per-attachment cap; oversized input fails loudly, never truncates.
public enum KdbxAttachments {
    /// Hard per-attachment cap (25 MiB): loud error, never truncation.
    public static let sizeLimitBytes = 26_214_400 // 25 MiB
}
