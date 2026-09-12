import Foundation

/// Top-level KDBX pipeline: raw file bytes → verified/authenticated/decrypted
/// → decompressed → inner header → XML → `KdbxDocument`.
///
/// KDBX 4.0/4.1 use the HMAC block stream (Encrypt-then-MAC); KDBX 3.1 is
/// read-only into the same document model (D-05) — writing a 3.1 document
/// always produces 4.0 (`KdbxWriter`).
public enum KdbxReader {

    /// Credentials for opening a database.
    public struct Credentials: Sendable {
        /// Master password, if used.
        public var password: String?
        /// Raw 32-byte key-file key, if used.
        public var keyFileKey: Data?

        /// Creates credentials; at least one component is required.
        public init(password: String? = nil, keyFileKey: Data? = nil) throws {
            if password == nil && keyFileKey == nil {
                throw KdbxError.malformedData
            }
            self.password = password
            self.keyFileKey = keyFileKey
        }

        func components() throws -> KdbxKeyComponents {
            try KdbxKeyComponents(password: password, keyFileKey: keyFileKey)
        }
    }

    /// Reads any supported KDBX version into the unified document model.
    public static func read(_ data: Data, credentials: Credentials) throws -> KdbxDocument {
        // Version detection happens after signature verification (4-byte-agnostic).
        var probe = ByteReader(data)
        let sig1 = try probe.readUInt32()
        let sig2 = try probe.readUInt32()
        guard sig1 == KdbxOuterHeader.signature1, sig2 == KdbxOuterHeader.signature2 else {
            throw KdbxError.corruptFile
        }
        let versionRaw = try probe.readUInt32()
        let major = (versionRaw >> 16) & 0xFFFF
        switch major {
        case 4: return try readV4(data, credentials: credentials)
        case 3: return try readV31(data, credentials: credentials)
        default: throw KdbxError.unsupportedVersion(versionRaw)
        }
    }

    // MARK: - KDBX 4.x

    static func readV4(_ data: Data, credentials: Credentials) throws -> KdbxDocument {
        let header = try KdbxOuterHeader.read(data)
        let components = try credentials.components()
        let transformed = try components.transformedKey(kdfParameters: header.kdfParameters)
        let baseKey = KdbxCrypto.hmacBaseKey(masterSeed: header.masterSeed, transformedKey: transformed)
        let headerHmacKey = KdbxCrypto.headerHmacKey(baseKey: baseKey)

        let headerByteCount = header.rawBytes.count
        try KdbxHeaderAuthentication.verify(
            data: data, headerByteCount: headerByteCount, headerHmacKey: headerHmacKey
        )

        // Cipher key + Encrypt-then-MAC: the HMAC block stream (starting after
        // header+64) authenticates the CIPHERTEXT — verify first, then decrypt.
        let cipherKey = KdbxCrypto.cipherKey(masterSeed: header.masterSeed, transformedKey: transformed)
        var reader = ByteReader(data)
        reader.offset = headerByteCount + 64
        let encrypted = try reader.readBytes(reader.remaining)
        let framed = try HmacBlockStream.read(encrypted, baseKey: baseKey)
        let compressed = try KdbxCrypto.outerCrypt(
            framed, cipherId: header.cipherId, key: cipherKey, iv: header.encryptionIV, encrypt: false
        )
        let payload: Data
        switch header.compression {
        case .gzip: payload = try Gzip.decompress(compressed)
        case .none: payload = compressed
        }

        // Inner header, then XML (both inside the decrypted payload).
        let (innerHeader, innerByteCount) = try KdbxInnerHeader.read(payload)
        let xmlData = payload.subdata(in: (payload.startIndex + innerByteCount) ..< payload.endIndex)
        let stream = try KdbxProtectedStream(id: innerHeader.innerStreamId, key: innerHeader.innerStreamKey)
        let reader2 = KdbxXML.Reader(data: xmlData, protectedStream: stream)
        var document = try reader2.parse()
        document.binaries = innerHeader.binaries
        document.version = KdbxVersion(major: (header.version >> 16) & 0xFFFF, minor: header.version & 0xFFFF)
        return document
    }

    // MARK: - KDBX 3.1 (read-only, unified model)

    static func readV31(_ data: Data, credentials: Credentials) throws -> KdbxDocument {
        var reader = ByteReader(data)
        _ = try reader.readBytes(8) // signature (verified by caller)
        let versionRaw = try reader.readUInt32()

        // 3.1 header fields use 2-byte lengths.
        var cipherId = KdbxCrypto.aesCipherUUID
        var compressionGzip = false
        var masterSeed = Data()
        var transformSeed = Data()
        var transformRounds: UInt64 = 0
        var encryptionIV = Data()
        var protectedStreamKey = Data()
        var streamStartBytes = Data()
        var innerRandomStreamID: KdbxInnerHeader.InnerStreamID = .salsa20

        while true {
            let id = try reader.readUInt8()
            let length = Int(try reader.readUInt16())
            guard length >= 0, length <= reader.remaining else { throw KdbxError.corruptFile }
            let value = try reader.readBytes(length)
            switch id {
            case 0: // end of header
                // 3.1 MAY carry the header SHA-256 here (32 bytes); KeePassXC
                // writes a 4-byte placeholder. Integrity is enforced by the
                // StreamStartBytes check after decryption either way.
                if value.count == 32 {
                    let headerBytes = data.subdata(in: data.startIndex ..< data.startIndex + reader.offset - 3 - 32)
                    guard Hmac.constantTimeEquals(Hmac.sha256(headerBytes), value) else { throw KdbxError.corruptFile }
                }
            case 2:
                guard let uuid = UUID(data: value) else { throw KdbxError.corruptFile }
                cipherId = uuid
            case 3: compressionGzip = (value.first == 1)
            case 4: masterSeed = value
            case 5: transformSeed = value
            case 6:
                var vr = ByteReader(value)
                transformRounds = try vr.readUInt64()
            case 7: encryptionIV = value
            case 8: protectedStreamKey = value
            case 9: streamStartBytes = value
            case 10:
                var vr = ByteReader(value)
                let raw = try vr.readInt32()
                guard let id = KdbxInnerHeader.InnerStreamID(rawValue: raw) else { throw KdbxError.unsupportedCipher }
                innerRandomStreamID = id
            default: break
            }
            if id == 0 { break }
        }

        // 3.1 KDF is fixed: AES-KDF with transformSeed/rounds.
        let composite = try credentials.components().compositeKey()
        guard transformRounds >= 1, transformRounds <= UInt64(UInt32.max) else { throw KdbxError.unsupportedKdfParameters }
        let transformed = try AESECBCipher.aesKdf(key32: composite, seed: transformSeed, rounds: transformRounds)
        // KDBX 3.1 final key (KeePassXC 2.7.12 Kdbx3Reader):
        // SHA-256(MasterSeed ‖ transformedKey). The AES-KDF itself already
        // includes a final SHA-256 over the ECB round output.
        let cipherKey = Hmac.sha256(masterSeed + transformed)

        guard cipherId == KdbxCrypto.aesCipherUUID else { throw KdbxError.unsupportedCipher }
        guard streamStartBytes.count == 32 else { throw KdbxError.corruptFile }

        // Decrypt whole body, then verify StreamStartBytes prefix (MAC-then-encrypt era).
        let body = try reader.readBytes(reader.remaining)
        let decrypted = try AESECBCipher.decryptCBC(body, key: cipherKey, iv: encryptionIV)
        guard Hmac.constantTimeEquals(decrypted.prefix(32), streamStartBytes) else { throw KdbxError.wrongCredentials }

        // HashedBlockStream (keepassxc HashedBlockStream.cpp):
        // [UInt32-LE index][32B SHA-256][Int32-LE size][data], terminated by a
        // zero-size block. Block payloads = optionally-gzipped XML.
        var blockReader = ByteReader(decrypted.subdata(in: decrypted.startIndex + 32 ..< decrypted.endIndex))
        var compressed = Data()
        var expectedIndex: UInt32 = 0
        while true {
            let index = try blockReader.readUInt32()
            guard index == expectedIndex else { throw KdbxError.corruptFile }
            expectedIndex &+= 1
            let storedHash = try blockReader.readBytes(32)
            let size = Int(try blockReader.readInt32())
            if size == 0 { break }
            guard size > 0, size <= blockReader.remaining else { throw KdbxError.corruptFile }
            let chunk = try blockReader.readBytes(size)
            guard Hmac.constantTimeEquals(Hmac.sha256(chunk), storedHash) else { throw KdbxError.corruptFile }
            compressed.append(chunk)
        }

        var xml = compressed
        if compressionGzip {
            xml = try Gzip.decompress(compressed)
        }

        // 3.1: XML after the block stream.
        let stream = try KdbxProtectedStream(id: innerRandomStreamID, key: protectedStreamKey)
        let xmlReader = KdbxXML.Reader(data: xml, protectedStream: stream)
        var document = try xmlReader.parse()
        document.version = KdbxVersion(
            major: (versionRaw >> 16) & 0xFFFF, minor: versionRaw & 0xFFFF
        )
        return document
    }
}
