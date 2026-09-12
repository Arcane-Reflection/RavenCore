import Foundation

/// KDBX key schedule and outer-cipher dispatch (keepass.info 4.1 spec).
///
/// With `R` = composite key, `T` = KDF(R, header params), `S` = master seed:
/// - cipher key        = SHA-256(S ‖ T)
/// - HMAC base key     = SHA-512(S ‖ T ‖ 0x01)
/// - header HMAC key   = SHA-512(0xFFFFFFFFFFFFFFFF ‖ base)
/// - block i HMAC key  = SHA-512(i_le64 ‖ base)
public enum KdbxCrypto {

    // MARK: - Well-known UUIDs (KeePassXC KeePass2.h; verified against corpus)

    /// AES-256-CBC outer cipher: 31C1F2E6-BF71-4350-BE58-05216AFC5AFF
    public static let aesCipherUUID = UUID(uuid: (0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
                                                  0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF))
    /// ChaCha20 outer cipher: D6038A2B-8B6F-4CB5-A524-339A31DBB59A
    public static let chacha20CipherUUID = UUID(uuid: (0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5,
                                                       0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A))
    /// AES-KDF (KDBX 4), KeePass XC 2.7 legacy spelling: C9D9F39A-628A-4460-BF74-0D08C18A4FEA
    /// (KeePassXC 2.7.12 writes THIS uuid in KDBX4 AES-KDF files; develop-tree
    /// exposes 7C02BB82-… — accept both on read, write the 2.7 one.)
    public static let aesKdfUUID = UUID(uuid: (0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60,
                                               0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA))
    /// AES-KDF alternate spelling seen in KeePassXC develop tree.
    public static let aesKdfUUIDAlt = UUID(uuid: (0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0,
                                                  0x92, 0x7D, 0x11, 0x4A, 0x00, 0x64, 0x82, 0x38))
    /// Argon2d: EF636DDF-8C29-444B-91F7-A9A403E30A0C
    public static let argon2dUUID = UUID(uuid: (0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B,
                                                0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C))
    /// Argon2id: 9E298B19-56DB-4773-B23D-FC3EC6F0A1E6
    public static let argon2idUUID = UUID(uuid: (0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73,
                                                 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6))

    // MARK: - Key schedule

    /// `cipherKey = SHA-256(S ‖ T)`.
    public static func cipherKey(masterSeed: Data, transformedKey: Data) -> Data {
        Hmac.sha256(masterSeed + transformedKey)
    }

    /// `baseKey = SHA-512(S ‖ T ‖ 0x01)`.
    public static func hmacBaseKey(masterSeed: Data, transformedKey: Data) -> Data {
        Hmac.sha512(masterSeed + transformedKey + Data([0x01]))
    }

    /// `headerHmacKey = SHA-512(0xFF×8 ‖ baseKey)`.
    public static func headerHmacKey(baseKey: Data) -> Data {
        Hmac.sha512(Data(repeating: 0xFF, count: 8) + baseKey)
    }

    /// `blockKey(i) = SHA-512(i_le64 ‖ baseKey)`.
    public static func blockHmacKey(baseKey: Data, index: UInt64) -> Data {
        var writer = ByteWriter()
        writer.writeUInt64(index)
        return Hmac.sha512(writer.data + baseKey)
    }

    // MARK: - Outer cipher

    /// Encrypts/decrypts the (already HMAC-framed) payload with the header's cipher.
    public static func outerCrypt(_ data: Data, cipherId: UUID, key: Data, iv: Data, encrypt: Bool) throws -> Data {
        switch cipherId {
        case aesCipherUUID:
            guard iv.count == 16 else { throw KdbxError.malformedData }
            return encrypt
                ? try AESECBCipher.encryptCBC(data, key: key, iv: iv)
                : try AESECBCipher.decryptCBC(data, key: key, iv: iv)
        case chacha20CipherUUID:
            guard iv.count == 12 else { throw KdbxError.malformedData }
            var cipher = try ChaCha20(key: key, nonce: iv)
            return cipher.apply(data)
        default:
            throw KdbxError.unsupportedCipher
        }
    }
}
