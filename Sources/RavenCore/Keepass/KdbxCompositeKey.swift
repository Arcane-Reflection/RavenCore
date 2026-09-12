import Foundation

/// Master key components and KDF dispatch (keepass.info 4.1 spec §"Computation of Keys").
///
/// `R = SHA-256(SHA-256(password) ‖ keyFileKey)` — components concatenated in
/// that order, each optional; `T = KDF(R, params from header field 11)`.
public struct KdbxKeyComponents: Sendable, Equatable {
    /// SHA-256 of the UTF-8 master password (nil when password-less).
    public var passwordHash: Data?
    /// Raw 32-byte key-file key (nil when no key file).
    public var keyFileKey: Data?

    /// Creates components; at least one must be present.
    public init(password: String?, keyFileKey: Data?) throws {
        if let password {
            self.passwordHash = Hmac.sha256(Data(password.utf8))
        }
        if let keyFileKey {
            self.keyFileKey = keyFileKey
        }
        if self.passwordHash == nil && self.keyFileKey == nil {
            throw KdbxError.malformedData
        }
    }

    /// `R = SHA-256(SHA-256(password) ‖ keyFileKey)` — the untransformed
    /// composite key.
    public func compositeKey() -> Data {
        var concatenated = Data()
        if let passwordHash { concatenated.append(passwordHash) }
        if let keyFileKey { concatenated.append(keyFileKey) }
        return Hmac.sha256(concatenated)
    }

    /// Transforms the composite key with the header's KDF parameters.
    public func transformedKey(kdfParameters: VariantDictionary) throws -> Data {
        let composite = compositeKey()
        guard case .byteArray(let uuidBytes)? = kdfParameters["$UUID"],
              let uuid = UUID(data: uuidBytes) else {
            throw KdbxError.unsupportedKdfParameters
        }
        switch uuid {
        case KdbxCrypto.argon2dUUID, KdbxCrypto.argon2idUUID:
            return try Self.transformArgon2(composite, kdfParameters, isArgon2id: uuid == KdbxCrypto.argon2idUUID)
        case KdbxCrypto.aesKdfUUID, KdbxCrypto.aesKdfUUIDAlt:
            return try Self.transformAESKdf(composite, kdfParameters)
        default:
            throw KdbxError.unsupportedKdf
        }
    }

    private static func transformArgon2(_ composite: Data, _ kdf: VariantDictionary, isArgon2id: Bool) throws -> Data {
        // KeePassXC emits I/M as UInt64 and P as UInt32 in the wild; accept
        // either integer width for every numeric parameter.
        func u32(_ key: String) -> UInt32? {
            if let v = kdf.uint32(key) { return v }
            if let v = kdf.uint64(key), v <= UInt64(UInt32.max) { return UInt32(v) }
            return nil
        }
        func u64(_ key: String) -> UInt64? {
            if let v = kdf.uint64(key) { return v }
            if let v = kdf.uint32(key) { return UInt64(v) }
            return nil
        }
        guard case .byteArray(let salt)? = kdf["S"], salt.count >= 8,
              let iterations = u32("I"), iterations >= 1,
              let memoryBytes = u64("M"), memoryBytes >= 8 * 1024,
              let parallelism = u32("P"), parallelism >= 1 else {
            throw KdbxError.unsupportedKdfParameters
        }
        // File unit for M is BYTES (KeePassXC writes KiB × 1024).
        let memoryKiB = memoryBytes / 1024
        // Clamp DoS vectors (threat T-02-03) without rejecting legitimate
        // desktop-created files (KeePassXC uses P up to core count).
        guard memoryKiB >= 8, memoryKiB <= 4_194_304, iterations <= 1 << 24, parallelism <= 16 else {
            throw KdbxError.unsupportedKdfParameters
        }
        // Version V must be 0x13 (Argon2 1.3); K (secret) and A (associated
        // data) are not supported by this implementation.
        guard kdf.uint32("V") == 0x13 else { throw KdbxError.unsupportedKdfParameters }
        guard kdf["K"] == nil, kdf["A"] == nil else { throw KdbxError.unsupportedKdfParameters }

        // Boundary mapping (FW-03): the kdbx-layer guards above are strictly
        // tighter than KeyDerivation's, so this catch is belt-and-braces — but
        // the module convention is that only `KdbxError` ever escapes a kdbx
        // read, never a foreign error type.
        do {
            if isArgon2id {
                return try KeyDerivation.argon2id(
                    password: composite, salt: salt,
                    memoryKiB: Int(memoryKiB), timeCost: Int(iterations), parallelism: Int(parallelism)
                )
            }
            return try KeyDerivation.argon2d(
                password: composite, salt: salt,
                memoryKiB: Int(memoryKiB), timeCost: Int(iterations), parallelism: Int(parallelism)
            )
        } catch {
            throw KdbxError.unsupportedKdfParameters
        }
    }

    private static func transformAESKdf(_ composite: Data, _ kdf: VariantDictionary) throws -> Data {
        guard case .byteArray(let seed)? = kdf["S"], seed.count == 32,
              let rounds = kdf.uint64("R"), rounds >= 1 else {
            throw KdbxError.unsupportedKdfParameters
        }
        // Header field 11's `R` is hostile input: the KDF transform runs
        // BEFORE the header HMAC check, so an absurd round count would hang
        // the open path unboundedly. Bound to the interop-sane ceiling
        // (KeePassXC benchmark scale, see `AESECBCipher.maxKdfRounds`) — the
        // same clamp philosophy as the Argon2 guard above (T-02-03).
        guard rounds <= AESECBCipher.maxKdfRounds else {
            throw KdbxError.unsupportedKdfParameters
        }
        return try AESECBCipher.aesKdf(key32: composite, seed: seed, rounds: rounds)
    }
}

extension UUID {
    /// KDBX serializes UUIDs as 16 raw bytes; XML Base64-encodes the same bytes.
    public init?(data: Data) {
        guard data.count == 16 else { return nil }
        let b = (0..<16).map { data[data.startIndex + $0] }
        self = UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                           b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }

    /// The 16 raw bytes of this UUID (KDBX wire order).
    public var data: Data {
        withUnsafeBytes(of: uuid) { Data($0) }
    }
}
