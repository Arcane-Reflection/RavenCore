import XCTest
@testable import RavenCore

/// Composite key derivation, KDF dispatch, key schedule, and header/block
/// stream framing. Expected values are recomputed in-test from the spec
/// formulas (oracle-by-construction) to catch implementation drift.
final class KdbxCompositeKeyTests: XCTestCase {

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    func testCompositeKeyFormula() throws {
        // R = SHA-256(SHA-256(password) ‖ keyFileKey)
        let components = try KdbxKeyComponents(password: "password", keyFileKey: Data(repeating: 0xAB, count: 32))
        var manual = Hmac.sha256(Data("password".utf8))
        manual.append(Data(repeating: 0xAB, count: 32))
        XCTAssertEqual(components.compositeKey(), Hmac.sha256(manual))
        XCTAssertEqual(components.compositeKey().count, 32)
    }

    func testPasswordOnlyAndKeyFileOnly() throws {
        let pwOnly = try KdbxKeyComponents(password: "password", keyFileKey: nil)
        let kfOnly = try KdbxKeyComponents(password: nil, keyFileKey: Data(repeating: 1, count: 32))
        XCTAssertEqual(pwOnly.compositeKey(), Hmac.sha256(Hmac.sha256(Data("password".utf8))))
        XCTAssertEqual(kfOnly.compositeKey(), Hmac.sha256(Data(repeating: 1, count: 32)))
        XCTAssertNotEqual(pwOnly.compositeKey(), kfOnly.compositeKey())
    }

    func testEmptyComponentsRejected() {
        XCTAssertThrowsError(try KdbxKeyComponents(password: nil, keyFileKey: nil)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
    }

    /// M file unit = BYTES (KeePassXC writes KiB × 1024).
    private func argon2idKDF(memoryBytes: UInt32 = 65_536 * 1024, iterations: UInt32 = 2) -> VariantDictionary {
        var kdf = VariantDictionary()
        kdf["$UUID"] = .byteArray(KdbxCrypto.argon2idUUID.data)
        kdf["V"] = .uint32(0x13)
        kdf["I"] = .uint32(iterations)
        kdf["M"] = .uint32(memoryBytes)
        kdf["P"] = .uint32(2)
        kdf["S"] = .byteArray(Data(repeating: 0x55, count: 32))
        return kdf
    }

    func testArgon2idDispatch() throws {
        let components = try KdbxKeyComponents(password: "password", keyFileKey: nil)
        let transformed = try components.transformedKey(kdfParameters: argon2idKDF())
        let expected = try KeyDerivation.argon2id(
            password: components.compositeKey(),
            salt: Data(repeating: 0x55, count: 32),
            memoryKiB: 65_536, timeCost: 2, parallelism: 2
        )
        XCTAssertEqual(transformed, expected)
    }

    func testArgon2dDispatch() throws {
        var kdf = argon2idKDF(memoryBytes: 8_192 * 1024, iterations: 1)
        kdf["$UUID"] = .byteArray(KdbxCrypto.argon2dUUID.data)
        let components = try KdbxKeyComponents(password: "password", keyFileKey: nil)
        let transformed = try components.transformedKey(kdfParameters: kdf)
        let expected = try KeyDerivation.argon2d(
            password: components.compositeKey(),
            salt: Data(repeating: 0x55, count: 32),
            memoryKiB: 8_192, timeCost: 1, parallelism: 2
        )
        XCTAssertEqual(transformed, expected)
    }

    func testUnknownKDFRejected() throws {
        var kdf = argon2idKDF()
        kdf["$UUID"] = .byteArray(Data(repeating: 0xEE, count: 16))
        let components = try KdbxKeyComponents(password: "password", keyFileKey: nil)
        XCTAssertThrowsError(try components.transformedKey(kdfParameters: kdf)) { error in
            XCTAssertEqual(error as? KdbxError, .unsupportedKdf)
        }
    }

    func testAbsurdKDFParametersRejected() throws {
        let components = try KdbxKeyComponents(password: "password", keyFileKey: nil)
        // 5 GiB in bytes — beyond the 4 MiB-KiB clamp. u64 type required.
        var absurd = argon2idKDF(iterations: 1)
        absurd["M"] = .uint64(UInt64(5) * 1024 * 1024 * 1024)
        XCTAssertThrowsError(try components.transformedKey(kdfParameters: absurd)) { error in
            XCTAssertEqual(error as? KdbxError, .unsupportedKdfParameters)
        }
    }

    /// FW-01: a hostile KDBX 4 header declaring an absurd AES-KDF round count
    /// must fail FAST with a typed error — the KDF transform runs before the
    /// header HMAC check, so nothing authenticates the file first. The wall-
    /// clock assert documents the "hang" regression (a bound of `Int.max`
    /// would never return at all).
    func testHostileAESKdfRoundsRejectedFast() throws {
        var kdf = VariantDictionary()
        kdf["$UUID"] = .byteArray(KdbxCrypto.aesKdfUUID.data)
        kdf["V"] = .uint32(0x01)
        kdf["R"] = .uint64(UInt64(1) << 40)
        kdf["S"] = .byteArray(Data(repeating: 0x66, count: 32))
        let components = try KdbxKeyComponents(password: "password", keyFileKey: nil)

        let start = Date()
        XCTAssertThrowsError(try components.transformedKey(kdfParameters: kdf)) { error in
            XCTAssertEqual(error as? KdbxError, .unsupportedKdfParameters)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
    }

    /// FW-01: the primitive itself enforces the same ceiling, which covers the
    /// KDBX 3.1 path (transformRounds comes straight from header field 6).
    func testAESKdfPrimitiveRejectsRoundsAboveCeiling() {
        XCTAssertThrowsError(try AESECBCipher.aesKdf(
            key32: Data(repeating: 1, count: 32),
            seed: Data(repeating: 2, count: 32),
            rounds: AESECBCipher.maxKdfRounds + 1
        )) { error in
            XCTAssertEqual(error as? KdbxError, .unsupportedKdfParameters)
        }
    }

    /// FW-01: round counts at the KeePassXC benchmark scale (the rv-aeskdf.kdbx
    /// fixture uses 600k) stay inside the ceiling — the bound rejects hostile
    /// files, not legitimate desktop-created ones.
    func testAESKdfAcceptsInteropRoundCounts() throws {
        let transformed = try AESECBCipher.aesKdf(
            key32: Data(repeating: 1, count: 32),
            seed: Data(repeating: 2, count: 32),
            rounds: 600_000
        )
        XCTAssertEqual(transformed.count, 32)
    }

    /// FW-03: below the kdbx-layer memory floor the failure is the module's
    /// own typed error — a foreign `KeyDerivationError` never escapes a kdbx
    /// read.
    func testKdbxMemoryFloorFiresWithKdbxErrorType() throws {
        let components = try KdbxKeyComponents(password: "password", keyFileKey: nil)
        // 4 KiB in bytes — below the 8 KiB spec floor both layers enforce.
        var kdf = argon2idKDF(memoryBytes: 4 * 1024, iterations: 1)
        XCTAssertThrowsError(try components.transformedKey(kdfParameters: kdf)) { error in
            XCTAssertEqual(error as? KdbxError, .unsupportedKdfParameters)
        }
    }

    /// FW-03: 8 KiB ≤ M < 8 MiB is spec-legal Argon2 and desktop tools do
    /// write it — after the deliberate bound alignment both layers accept it
    /// instead of failing on an accidental interop strictness.
    func testSmallArgon2MemoryWithinSpecDerives() throws {
        let kdf = argon2idKDF(memoryBytes: 1024 * 1024, iterations: 1) // 1 MiB
        let components = try KdbxKeyComponents(password: "password", keyFileKey: nil)
        let transformed = try components.transformedKey(kdfParameters: kdf)
        XCTAssertEqual(transformed, try KeyDerivation.argon2id(
            password: components.compositeKey(),
            salt: Data(repeating: 0x55, count: 32),
            memoryKiB: 1024, timeCost: 1, parallelism: 2
        ))
    }

    /// FI-04: the constant-time comparison backing every MAC/tag/hash check.
    func testConstantTimeEquals() {
        let a = Data([0x01, 0x02, 0x03])
        XCTAssertTrue(Hmac.constantTimeEquals(a, Data([0x01, 0x02, 0x03])))
        XCTAssertFalse(Hmac.constantTimeEquals(a, Data([0x01, 0x02, 0x04])))
        XCTAssertFalse(Hmac.constantTimeEquals(a, Data([0x04, 0x02, 0x03])))
        XCTAssertFalse(Hmac.constantTimeEquals(a, Data([0x01, 0x02])))
        XCTAssertTrue(Hmac.constantTimeEquals(Data(), Data()))
        // Slices compare by content, matching the `==` semantics it replaces.
        let base = Data(repeating: 9, count: 8)
        XCTAssertTrue(Hmac.constantTimeEquals(base.prefix(4), base[2..<6].prefix(4)))
    }

    func testKeyScheduleFormulas() throws {
        let seed = Data(repeating: 0x77, count: 32)
        let transformed = Data(repeating: 0x88, count: 32)

        let base = KdbxCrypto.hmacBaseKey(masterSeed: seed, transformedKey: transformed)
        XCTAssertEqual(base, Hmac.sha512(seed + transformed + Data([0x01])))

        XCTAssertEqual(KdbxCrypto.cipherKey(masterSeed: seed, transformedKey: transformed), Hmac.sha256(seed + transformed))
        XCTAssertEqual(KdbxCrypto.headerHmacKey(baseKey: base), Hmac.sha512(Data(repeating: 0xFF, count: 8) + base))
        XCTAssertEqual(KdbxCrypto.blockHmacKey(baseKey: base, index: 7), Hmac.sha512({
            var w = ByteWriter(); w.writeUInt64(7); return w.data
        }() + base))
    }
}

final class KdbxHeaderTests: XCTestCase {

    func testHeaderRoundTripPreservesUnknownFields() throws {
        var kdf = VariantDictionary()
        kdf["$UUID"] = .byteArray(KdbxCrypto.argon2idUUID.data)
        kdf["V"] = .uint32(0x13)
        kdf["I"] = .uint32(2)
        kdf["M"] = .uint32(65_536)
        kdf["P"] = .uint32(2)
        kdf["S"] = .byteArray(Data(repeating: 3, count: 32))

        let header = KdbxOuterHeader(
            version: KdbxOuterHeader.version41,
            cipherId: KdbxCrypto.aesCipherUUID,
            compression: .gzip,
            masterSeed: Data(repeating: 1, count: 32),
            encryptionIV: Data(repeating: 2, count: 16),
            kdfParameters: kdf,
            publicCustomData: nil,
            unknownFields: [OpaqueField(id: 13, value: Data("plugin-data".utf8))],
            rawBytes: Data()
        )

        let bytes = header.serialize()
        let restored = try KdbxOuterHeader.read(bytes)
        XCTAssertEqual(restored, header)
        XCTAssertEqual(restored.unknownFields.first?.id, 13)
    }

    func testBadSignatureRejected() {
        XCTAssertThrowsError(try KdbxOuterHeader.read(Data("garbage".utf8))) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }
    }

    func testFutureVersionRejected() {
        var writer = ByteWriter()
        writer.writeUInt32(KdbxOuterHeader.signature1)
        writer.writeUInt32(KdbxOuterHeader.signature2)
        writer.writeUInt32(0x0005_0000)
        writer.writeUInt8(0) // end of header
        writer.writeInt32(0)
        XCTAssertThrowsError(try KdbxOuterHeader.read(writer.data)) { error in
            guard case KdbxError.unsupportedVersion = error as! KdbxError else {
                return XCTFail("expected unsupportedVersion")
            }
        }
    }
}

final class HmacBlockStreamTests: XCTestCase {

    func testRoundTrip() throws {
        let base = KdbxCrypto.hmacBaseKey(masterSeed: Data(repeating: 1, count: 32), transformedKey: Data(repeating: 2, count: 32))
        let payload = Data((0..<2_500_000).map { UInt8($0 % 251) })
        let framed = try HmacBlockStream.serialize(payload, baseKey: base, blockSize: 1_048_576)
        XCTAssertEqual(try HmacBlockStream.read(framed, baseKey: base), payload)
    }

    func testTamperedCiphertextRejectedBeforeDecrypt() throws {
        let base = KdbxCrypto.hmacBaseKey(masterSeed: Data(repeating: 1, count: 32), transformedKey: Data(repeating: 2, count: 32))
        var framed = try HmacBlockStream.serialize(Data(repeating: 9, count: 1000), baseKey: base)
        framed[framed.count - 20] ^= 0xFF // flip inside the first block's ciphertext
        XCTAssertThrowsError(try HmacBlockStream.read(framed, baseKey: base)) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }
    }

    // MARK: Truncation / hostile-framing matrix (re-review follow-up 3, Nyquist item 4)

    private let matrixBaseKey = KdbxCrypto.hmacBaseKey(
        masterSeed: Data(repeating: 1, count: 32), transformedKey: Data(repeating: 2, count: 32)
    )

    /// Every structural truncation point — inside the header block, inside a
    /// mid-stream block, inside the final terminator — fails as the typed
    /// `corruptFile`, never a crash or partial release. Frame layout for a
    /// 1500-byte payload at blockSize 1000:
    /// block0 = 32+4+1000 B, block1 = 32+4+500 B, terminator = 32+4 B (1608 B total).
    func testTruncatedStreamRejectedAtEveryStructuralPosition() throws {
        let framed = try HmacBlockStream.serialize(Data(repeating: 9, count: 1500), baseKey: matrixBaseKey, blockSize: 1000)
        XCTAssertEqual(framed.count, 1608)

        // 0/1/35: below the 36-byte structural minimum; 36: size declared but
        // no ciphertext bytes follow; 1035/1036: header block cut short / no
        // bytes for the next block; 1300/1571: mid-stream block cut short by
        // many/one bytes; 1572/1607: terminator absent / cut short by one byte.
        for cut in [0, 1, 35, 36, 1035, 1036, 1300, 1571, 1572, 1607] {
            XCTAssertThrowsError(try HmacBlockStream.read(framed.prefix(cut), baseKey: matrixBaseKey)) { error in
                XCTAssertEqual(error as? KdbxError, .corruptFile, "cut at \(cut)")
            }
        }
    }

    /// Hostile size fields are rejected at the bounds check before any HMAC
    /// work or ciphertext indexing: a negative Int32 and a size larger than
    /// the remaining bytes both fail typed.
    func testHostileSizeFieldsRejected() {
        func hostileBlock(size: Int32) -> Data {
            var writer = ByteWriter()
            writer.writeBytes(Data(repeating: 0, count: 32)) // stored HMAC — never reached
            writer.writeInt32(size)
            return writer.data
        }
        XCTAssertThrowsError(try HmacBlockStream.read(hostileBlock(size: -1), baseKey: matrixBaseKey)) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }
        XCTAssertThrowsError(try HmacBlockStream.read(hostileBlock(size: Int32.max), baseKey: matrixBaseKey)) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }
    }

    /// The terminator's authenticity is enforced: a zero-size block whose
    /// stored HMAC does not verify is rejected — a stream cannot be ended
    /// early with a forged empty block. The genuine empty stream round-trips.
    func testForgedTerminatorRejectedAndEmptyStreamRoundTrips() throws {
        var forged = ByteWriter()
        forged.writeBytes(Data(repeating: 0, count: 32))
        forged.writeInt32(0)
        XCTAssertThrowsError(try HmacBlockStream.read(forged.data, baseKey: matrixBaseKey)) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }

        let empty = try HmacBlockStream.serialize(Data(), baseKey: matrixBaseKey)
        XCTAssertEqual(empty.count, 36)
        XCTAssertEqual(try HmacBlockStream.read(empty, baseKey: matrixBaseKey), Data())
    }

    /// Tampering with the stored digest or the size field breaks
    /// authentication before any ciphertext is released (EtM ordering). The
    /// 32-byte digest length is fixed by the framing, so a short digest is
    /// exactly the sub-36-byte truncation case covered above.
    func testTamperedStoredHmacAndSizeRejected() throws {
        var tamperedHmac = try HmacBlockStream.serialize(Data(repeating: 7, count: 40), baseKey: matrixBaseKey, blockSize: 100)
        tamperedHmac[10] ^= 0xFF // inside the first block's stored digest
        XCTAssertThrowsError(try HmacBlockStream.read(tamperedHmac, baseKey: matrixBaseKey)) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }

        var tamperedSize = try HmacBlockStream.serialize(Data(repeating: 7, count: 40), baseKey: matrixBaseKey, blockSize: 100)
        tamperedSize[33] ^= 0xFF // inside the first block's size field
        XCTAssertThrowsError(try HmacBlockStream.read(tamperedSize, baseKey: matrixBaseKey)) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }
    }

    /// Bytes after the authenticated empty block are outside the stream —
    /// read terminates at the terminator (pinned so the framing semantics
    /// stay explicit).
    func testBytesAfterTerminatorAreOutsideStream() throws {
        let framed = try HmacBlockStream.serialize(Data("payload".utf8), baseKey: matrixBaseKey)
        var withTrailing = framed
        withTrailing.append(Data(repeating: 0xAA, count: 64))
        XCTAssertEqual(try HmacBlockStream.read(withTrailing, baseKey: matrixBaseKey), Data("payload".utf8))
    }
}
