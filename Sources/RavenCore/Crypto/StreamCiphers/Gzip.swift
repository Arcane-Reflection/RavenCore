import Compression
import Foundation

/// gzip container (RFC 1952) around Apple's Compression-framework raw DEFLATE.
///
/// KDBX's CompressionFlags=1 is plain gzip; Apple exposes raw deflate only
/// (COMPRESSION_ZLIB — despite the name it produces/consumes raw DEFLATE with
/// no zlib header), so the header/trailer is handled here. Zero dependencies.
public enum Gzip {
    /// Wraps `data` in a minimal gzip container (no name/comment/extras,
    /// zero mtime — deterministic output).
    public static func compress(_ data: Data) throws -> Data {
        let deflated = try rawDeflate(data)
        var out = ByteWriter()
        out.writeBytes(Data([0x1F, 0x8B, 0x08])) // magic + deflate
        out.writeUInt8(0) // flags
        out.writeUInt32(0) // mtime (omitted — deterministic output)
        out.writeUInt8(0) // XFL
        out.writeUInt8(0xFF) // OS = unknown
        out.writeBytes(deflated)
        out.writeUInt32(CRC32.checksum(data))
        out.writeUInt32(UInt32(truncatingIfNeeded: data.count)) // ISIZE
        return out.data
    }

    /// Parses the gzip container and inflates the payload, verifying the
    /// CRC-32/ISIZE trailer. Inflation is bounded by a resource ceiling (FI-01).
    public static func decompress(_ data: Data) throws -> Data {
        var reader = ByteReader(data)
        guard try reader.readUInt16() == 0x8B1F, // magic (LE read of 1F 8B)
              try reader.readUInt8() == 0x08 else { throw KdbxError.malformedData }
        let flags = try reader.readUInt8()
        // RFC 1952 §2.3.1: FLG bits 5-7 are reserved and must be zero — no
        // compliant writer sets them, so a set bit means corruption. FTEXT
        // (0x01) is informational and stays accepted.
        guard flags & 0xE0 == 0 else { throw KdbxError.malformedData }
        _ = try reader.readBytes(5) // mtime(4) + XFL
        _ = try reader.readUInt8() // OS
        if flags & 0x04 != 0 { // FEXTRA
            let extraLen = Int(try reader.readUInt16())
            guard extraLen >= 0, extraLen <= reader.remaining else { throw KdbxError.malformedData }
            _ = try reader.readBytes(extraLen)
        }
        if flags & 0x08 != 0 { // FNAME: zero-terminated
            while try reader.readUInt8() != 0 { }
        }
        if flags & 0x10 != 0 { // FCOMMENT
            while try reader.readUInt8() != 0 { }
        }
        if flags & 0x02 != 0 { // FHCRC
            _ = try reader.readBytes(2)
        }
        guard reader.remaining > 8 else { throw KdbxError.malformedData }
        let deflated = try reader.readBytes(reader.remaining - 8) // payload runs to len-8
        let inflated = try rawInflate(deflated)

        var trailerReader = ByteReader(try reader.readBytes(8))
        let storedCRC = try trailerReader.readUInt32()
        let storedSize = try trailerReader.readUInt32()
        guard CRC32.checksum(inflated) == storedCRC,
              UInt32(truncatingIfNeeded: inflated.count) == storedSize else {
            throw KdbxError.malformedData
        }
        return inflated
    }

    // MARK: - Raw DEFLATE via Compression framework

    private static func rawDeflate(_ data: Data) throws -> Data {
        guard !data.isEmpty else { return Data() }
        // Worst-case stored-block overhead: ~5 bytes per 64 KiB + terminator.
        let destinationCapacity = data.count + 4096 + (data.count / 65_535) * 5
        var destination = Data(count: destinationCapacity)
        let written = destination.withUnsafeMutableBytes { destBuf in
            data.withUnsafeBytes { srcBuf in
                compression_encode_buffer(
                    destBuf.bindMemory(to: UInt8.self).baseAddress!, destinationCapacity,
                    srcBuf.bindMemory(to: UInt8.self).baseAddress!, data.count,
                    nil, COMPRESSION_ZLIB
                )
            }
        }
        guard written > 0 else { throw KdbxError.malformedData }
        destination.removeSubrange(written..<destination.count)
        return destination
    }

    private static func rawInflate(_ data: Data) throws -> Data {
        // Resource ceiling (02-REVIEW-FULL FI-01): DEFLATE's theoretical worst
        // case is ~1032:1 expansion, so any real stream stays far below the
        // 2048× ratio allowance; the absolute 256 MiB cap bounds the growing
        // retry loop's peak buffer (previously ~1 GiB). Decompression is only
        // reachable after credential authentication in both KDBX flavors, so
        // this is resource hygiene rather than a hostile-input bound.
        let ceiling = min(max(2048 * data.count, 1 << 20), 256 << 20)
        // Inflate in exponentially growing chunks (deflate output size is unknown upfront).
        var capacity = max(data.count * 2, 4096)
        while true {
            var destination = Data(count: capacity)
            let written = destination.withUnsafeMutableBytes { destBuf in
                data.withUnsafeBytes { srcBuf in
                    compression_decode_buffer(
                        destBuf.bindMemory(to: UInt8.self).baseAddress!, capacity,
                        srcBuf.bindMemory(to: UInt8.self).baseAddress!, data.count,
                        nil, COMPRESSION_ZLIB
                    )
                }
            }
            if written < capacity {
                guard written > 0 else { throw KdbxError.malformedData }
                destination.removeSubrange(written..<destination.count)
                return destination
            }
            capacity *= 2
            if capacity > ceiling { throw KdbxError.malformedData }
        }
    }
}
