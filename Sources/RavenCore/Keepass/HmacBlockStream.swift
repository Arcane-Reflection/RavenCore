import Foundation

/// HMAC-protected block stream (keepass.info 4.1 spec §"HMAC-protected Block Stream").
///
/// Encrypt-then-MAC: each block is `[32B HMAC-SHA-256(i ‖ s_le ‖ C)] ‖ [Int32-LE s] ‖ C`.
/// Verification always precedes decryption (threat T-02-02); a tampered block
/// fails with `corruptFile` before any plaintext exists. Default block size is
/// 1 MiB, terminated by an empty block (s = 0).
public enum HmacBlockStream {

    /// Spec default block size (1 MiB).
    public static let defaultBlockSize = 1_048_576

    /// Reads and verifies the block stream, returning the concatenated plaintext
    /// (which is still encrypted at the outer layer — EtM framing only).
    public static func read(_ data: Data, baseKey: Data) throws -> Data {
        var reader = ByteReader(data)
        var output = Data()
        var index: UInt64 = 0
        while true {
            guard reader.remaining >= 36 else { throw KdbxError.corruptFile }
            let storedHmac = try reader.readBytes(32)
            let size = Int(try reader.readInt32())
            guard size >= 0, size <= reader.remaining else { throw KdbxError.corruptFile }
            let ciphertext = try reader.readBytes(size)

            var indexWriter = ByteWriter()
            indexWriter.writeUInt64(index)
            var sizeWriter = ByteWriter()
            sizeWriter.writeInt32(Int32(size))
            let message = indexWriter.data + sizeWriter.data + ciphertext
            let key = KdbxCrypto.blockHmacKey(baseKey: baseKey, index: index)
            guard Hmac.constantTimeEquals(Hmac.hmacSHA256(key: key, message: message), storedHmac) else {
                throw KdbxError.corruptFile
            }
            if size == 0 { return output }
            output.append(ciphertext)
            index &+= 1
        }
    }

    /// Frames `payload` into HMAC-verified blocks terminated by an empty block.
    public static func serialize(_ payload: Data, baseKey: Data, blockSize: Int = defaultBlockSize) throws -> Data {
        guard blockSize > 0 else { throw KdbxError.malformedData }
        var writer = ByteWriter()
        var index: UInt64 = 0
        var offset = 0
        while true {
            let chunk = payload.subdata(in: (payload.startIndex + offset) ..< (payload.startIndex + min(offset + blockSize, payload.count)))
            let size = chunk.count
            var indexWriter = ByteWriter()
            indexWriter.writeUInt64(index)
            var sizeWriter = ByteWriter()
            sizeWriter.writeInt32(Int32(size))
            let message = indexWriter.data + sizeWriter.data + chunk
            let key = KdbxCrypto.blockHmacKey(baseKey: baseKey, index: index)
            writer.writeBytes(Hmac.hmacSHA256(key: key, message: message))
            writer.writeInt32(Int32(size))
            writer.writeBytes(chunk)
            offset += size
            index &+= 1
            if size == 0 { return writer.data }
        }
    }
}
