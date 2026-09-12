import Foundation

/// Top-level KDBX 4 write pipeline: `KdbxDocument` → XML → inner header →
/// gzip → HMAC block stream → outer encrypt → header + hash + HMAC.
///
/// Fresh ⟳ values (master seed, IV, inner stream key, KDF salt) are generated
/// on every write per spec. A 3.1 document is always written as 4.0 (D-05:
/// read 3.1, save 4.0 — never write 3.1).
public enum KdbxWriter {

    /// Write options; defaults match KeePassXC's default database settings.
    public struct Options: Sendable {
        /// Outer cipher UUID.
        public var cipherId: UUID = KdbxCrypto.aesCipherUUID // AES-256-CBC
        /// KDF parameter dictionary (`$UUID` selects the KDF).
        public var kdfParameters: VariantDictionary = VariantDictionary()
        /// Payload compression.
        public var compression: KdbxOuterHeader.Compression = .gzip
        /// Target file version.
        public var version: KdbxVersion = .v40

        /// Argon2id with the engine defaults (m=64 MiB, t=3, p=2, v=0x13).
        /// Value types mirror KeePassXC's emission (I/M as UInt64, P/V as
        /// UInt32) — required for KeePassXC to accept our files.
        public static func argon2idDefaults() -> Options {
            var kdf = VariantDictionary()
            kdf["$UUID"] = .byteArray(KdbxCrypto.argon2idUUID.data)
            kdf["V"] = .uint32(0x13)
            kdf["I"] = .uint64(UInt64(KeyDerivation.argon2TimeCost))
            kdf["M"] = .uint64(UInt64(KeyDerivation.argon2MemoryKiB) * 1024) // file unit = bytes (KeePassXC ×1024)
            kdf["P"] = .uint32(UInt32(KeyDerivation.argon2Parallelism))
            var options = Options()
            options.kdfParameters = kdf
            return options
        }

        /// AES-KDF (KDBX 4 variant) for interop testing.
        public static func aesKdf(rounds: UInt32 = 600_000) -> Options {
            var kdf = VariantDictionary()
            kdf["$UUID"] = .byteArray(KdbxCrypto.aesKdfUUID.data)
            kdf["V"] = .uint32(0x01)
            kdf["R"] = .uint64(UInt64(rounds))
            var options = Options()
            options.kdfParameters = kdf
            return options
        }
    }

    /// Serializes the document. `credentials` supply the master key material;
    /// binaries referenced by entries must be provided via `binaries` (indexed)
    /// — dangling or negative refs (e.g. a 3.1-sourced document whose binaries
    /// remain opaque in Meta, FI-07) throw `malformedData` instead of silently
    /// producing a file other readers may reject.
    public static func write(
        _ document: KdbxDocument,
        credentials: KdbxReader.Credentials,
        binaries: [KdbxInnerHeader.Binary] = [],
        options: Options = .argon2idDefaults()
    ) throws -> Data {
        // 3.1 documents upgrade to 4.0 unconditionally (D-05).
        var doc = document
        doc.version = options.version

        // ⟳ values are always regenerated.
        let masterSeed = SecureRandom.bytes(count: 32)
        let ivSize = options.cipherId == KdbxCrypto.chacha20CipherUUID ? 12 : 16
        let encryptionIV = SecureRandom.bytes(count: ivSize)
        let innerStreamKey = SecureRandom.bytes(count: 64)
        var kdf = options.kdfParameters
        // KDF salt is 32 bytes for both supported KDFs (Argon2id and AES-KDF).
        kdf["S"] = .byteArray(SecureRandom.bytes(count: 32))

        let header = KdbxOuterHeader(
            version: (options.version.major << 16) | options.version.minor,
            cipherId: options.cipherId,
            compression: options.compression,
            masterSeed: masterSeed,
            encryptionIV: encryptionIV,
            kdfParameters: kdf,
            publicCustomData: nil,
            unknownFields: [],
            rawBytes: Data()
        )

        // Key schedule.
        let components = try credentials.components()
        let transformed = try components.transformedKey(kdfParameters: kdf)
        let baseKey = KdbxCrypto.hmacBaseKey(masterSeed: masterSeed, transformedKey: transformed)
        let headerHmacKey = KdbxCrypto.headerHmacKey(baseKey: baseKey)
        let cipherKey = KdbxCrypto.cipherKey(masterSeed: masterSeed, transformedKey: transformed)

        // XML → inner header → (gzip) → HMAC blocks → encrypt.
        let stream = try KdbxProtectedStream(id: .chacha20, key: innerStreamKey)
        let xmlWriter = KdbxXML.Writer(protectedStream: stream)
        let xml = xmlWriter.serialize(doc)

        var innerHeader = KdbxInnerHeader(innerStreamId: .chacha20, innerStreamKey: innerStreamKey)
        let pool = binaries.isEmpty ? doc.binaries : binaries
        try Self.validateBinaryRefs(doc.root, poolCount: pool.count)
        if !pool.isEmpty {
            innerHeader.binaries = try pool.map { binary in
                guard binary.content.count <= KdbxAttachments.sizeLimitBytes else {
                    throw KdbxError.attachmentTooLarge(limitBytes: KdbxAttachments.sizeLimitBytes)
                }
                return binary
            }
        }
        var payload = innerHeader.serialize()
        payload.append(xml)

        let compressed: Data
        switch options.compression {
        case .gzip: compressed = try Gzip.compress(payload)
        case .none: compressed = payload
        }
        // Encrypt-then-MAC (spec §Data Authentication): frame the CIPHERTEXT.
        let encrypted = try KdbxCrypto.outerCrypt(
            compressed, cipherId: options.cipherId, key: cipherKey, iv: encryptionIV, encrypt: true
        )
        let framed = try HmacBlockStream.serialize(encrypted, baseKey: baseKey)

        let headerBytes = header.serialize()
        return headerBytes
            + KdbxHeaderAuthentication.serialize(headerBytes: headerBytes, headerHmacKey: headerHmacKey)
            + framed
    }

    /// Enforces the documented `binaries` precondition (02-REVIEW-FULL FI-07):
    /// every entry `Binary Ref` — including history entries, which share the
    /// same pool — must index the pool that is actually written. A dangling
    /// or negative ref previously serialized verbatim, silently producing a
    /// file other readers may reject; it is now a loud error at the boundary.
    private static func validateBinaryRefs(_ group: KdbxGroup, poolCount: Int) throws {
        func validate(_ entry: KdbxEntry) throws {
            for binary in entry.binaries where binary.ref < 0 || binary.ref >= poolCount {
                throw KdbxError.malformedData
            }
            for historic in entry.history {
                try validate(historic)
            }
        }
        for entry in group.entries {
            try validate(entry)
        }
        for sub in group.groups {
            try validateBinaryRefs(sub, poolCount: poolCount)
        }
    }
}
