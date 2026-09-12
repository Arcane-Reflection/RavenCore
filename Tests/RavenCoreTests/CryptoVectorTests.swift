import XCTest
@testable import RavenCore

final class VariantDictionaryTests: XCTestCase {

    func testRoundTrip() throws {
        var dict = VariantDictionary()
        dict["$UUID"] = .byteArray(Data(repeating: 7, count: 16))
        dict["I"] = .uint32(3)
        dict["M"] = .uint32(65_536)
        dict["V"] = .uint32(0x13)
        dict["S"] = .byteArray(Data(repeating: 9, count: 32))
        dict["P"] = .uint32(2)

        let restored = try VariantDictionary(data: dict.serialize())
        XCTAssertEqual(restored, dict)
    }

    func testUnknownTypeTagPreserved() throws {
        // Hand-build: version + one unknown-type item (0x99) + terminator.
        var writer = ByteWriter()
        writer.writeUInt16(0x0100)
        writer.writeUInt8(0x99)
        let key = Data("WeirdKey".utf8)
        let value = Data([0xDE, 0xAD, 0xBE, 0xEF])
        writer.writeInt32(Int32(key.count))
        writer.writeBytes(key)
        writer.writeInt32(Int32(value.count))
        writer.writeBytes(value)
        writer.writeUInt8(0x00)

        let dict = try VariantDictionary(data: writer.data)
        XCTAssertNil(dict["WeirdKey"])
        XCTAssertEqual(dict.unknownItems.count, 1)
        XCTAssertEqual(dict.unknownItems[0].key, "WeirdKey")
        XCTAssertEqual(dict.unknownItems[0].value, value)
        // Re-serialization preserves the opaque item verbatim.
        let restored = try VariantDictionary(data: dict.serialize())
        XCTAssertEqual(restored.unknownItems, dict.unknownItems)
    }

    func testMissingTerminatorRejected() {
        var writer = ByteWriter()
        writer.writeUInt16(0x0100)
        writer.writeUInt8(0x04)
        writer.writeInt32(1)
        writer.writeBytes(Data("K".utf8))
        writer.writeInt32(4)
        writer.writeBytes(Data([1, 2, 3, 4]))
        // no 0x00 terminator
        XCTAssertThrowsError(try VariantDictionary(data: writer.data)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
    }

    func testWrongMajorVersionRejected() {
        var writer = ByteWriter()
        writer.writeUInt16(0x0300)
        writer.writeUInt8(0x00)
        XCTAssertThrowsError(try VariantDictionary(data: writer.data)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
    }

    func testByteReaderBounds() {
        var reader = ByteReader(Data([1, 2, 3]))
        XCTAssertThrowsError(try reader.readBytes(4)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
        XCTAssertThrowsError(try reader.readBytes(-1)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
    }
}

/// NIST SP 800-38A AES-256 vectors + AES-KDF self-consistency.
final class AESECBCipherTests: XCTestCase {

    // NIST SP 800-38A F.1.5 ECB-AES256.Encrypt, block 1
    func testECBVector() throws {
        let key = Data([0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4])
        let plaintext = Data([0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a])
        let expected = Data([0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8])
        XCTAssertEqual(try AESECBCipher.ecbEncryptBlock(plaintext, key: key), expected)
    }

    // NIST SP 800-38A F.2.5 CBC-AES256.Encrypt, block 1 (same key, IV F.2.5)
    func testCBCVector() throws {
        let key = Data([0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4])
        let iv = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        let plaintext = Data([0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                              0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51])
        let expectedPrefix = Data([0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6])
        let ciphertext = try AESECBCipher.encryptCBC(plaintext, key: key, iv: iv)
        XCTAssertEqual(ciphertext.prefix(16), expectedPrefix)
        XCTAssertEqual(ciphertext.count, 48) // 32 + PKCS7 pad block
        let decrypted = try AESECBCipher.decryptCBC(ciphertext, key: key, iv: iv)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testAesKdfSingleRoundMatchesManualECB() throws {
        let key = Data(repeating: 0x11, count: 32)
        let seed = Data(repeating: 0x22, count: 32)
        // One AES-KDF round == one ECB encryption of each 16-byte half, then
        // the KDF-final SHA-256 over the round output (KeePassXC semantics).
        let manualLeft = try AESECBCipher.ecbEncryptBlock(Data(key.prefix(16)), key: seed)
        let manualRight = try AESECBCipher.ecbEncryptBlock(Data(key.suffix(16)), key: seed)
        let kdf = try AESECBCipher.aesKdf(key32: key, seed: seed, rounds: 1)
        XCTAssertEqual(kdf, Hmac.sha256(manualLeft + manualRight))
    }
}

final class GzipTests: XCTestCase {

    func testRoundTripVariousSizes() throws {
        for size in [1, 1024, 1_048_576] {
            let original = Data((0..<size).map { UInt8(($0 * 31) % 251) })
            let compressed = try Gzip.compress(original)
            XCTAssertEqual(try Gzip.decompress(compressed), original, "size \(size)")
        }
    }

    func testCompressedOutputIsSmaller() throws {
        let original = Data(repeating: 0x41, count: 100_000)
        XCTAssertLessThan(try Gzip.compress(original).count, original.count / 10)
    }

    func testCorruptTrailerRejected() throws {
        var compressed = try Gzip.compress(Data(repeating: 7, count: 5000))
        compressed[compressed.count - 2] ^= 0xFF
        XCTAssertThrowsError(try Gzip.decompress(compressed)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
    }

    /// FI-01: DEFLATE's worst-case expansion is ~1032:1, so a legitimate
    /// highly-compressible stream stays well inside the 2048× ratio allowance.
    func testInflateAllowsRealStreamsAboveThousandToOneRatio() throws {
        let original = Data(count: 8 << 20) // 8 MiB of zeros ≈ 1000:1 compressed
        let compressed = try Gzip.compress(original)
        XCTAssertLessThan(compressed.count, original.count / 500)
        XCTAssertEqual(try Gzip.decompress(compressed), original)
    }

    /// FI-01: a stream inflating past the 256 MiB absolute ceiling fails as a
    /// typed error instead of peaking at ~1 GiB of retry buffers. The inflated
    /// size is beyond the ceiling no matter how good the ratio, so a real
    /// 300 MiB compressible payload is the honest bomb stand-in.
    func testInflateRejectsOutputBeyondCeiling() throws {
        let bombSource = Data(count: 300 << 20) // 300 MiB of zeros
        let compressed = try Gzip.compress(bombSource)
        XCTAssertLessThan(compressed.count, 1 << 20)
        XCTAssertThrowsError(try Gzip.decompress(compressed)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
    }

    // MARK: - Header-field matrix (re-review follow-up 4, Nyquist item 3)

    /// The sample payload every matrix case compresses; small so the matrix
    /// stays fast, large enough to exercise a real DEFLATE body.
    private static let sample = Data("gzip-header-field-matrix-payload".utf8)

    /// The raw DEFLATE body of `Gzip.compress` output (header/trailer stripped)
    /// so hand-built containers carry a genuinely decodable stream.
    private func rawDeflate(of data: Data) throws -> Data {
        let compressed = try Gzip.compress(data)
        return compressed.subdata(in: (compressed.startIndex + 10) ..< (compressed.endIndex - 8))
    }

    /// Assembles a gzip container by hand. Optional fields are written
    /// verbatim per the FLG bits (RFC 1952 §2.2 order: EXTRA, NAME, COMMENT,
    /// HCRC) — FNAME/FCOMMENT bytes must include their own zero terminator —
    /// and the trailer defaults to the correct CRC-32/ISIZE for `inflated`.
    private func container(
        magic: [UInt8] = [0x1F, 0x8B],
        cm: UInt8 = 0x08,
        flags: UInt8 = 0,
        extra: Data = Data(),
        extraLenOverride: UInt16? = nil,
        fname: Data = Data(),
        fcomment: Data = Data(),
        hcrc: Data = Data([0x00, 0x00]),
        payload: Data,
        trailer: Data? = nil,
        inflated: Data = Data()
    ) -> Data {
        var out = ByteWriter()
        out.writeBytes(Data(magic))
        out.writeUInt8(cm)
        out.writeUInt8(flags)
        out.writeUInt32(0) // mtime
        out.writeUInt8(0) // XFL
        out.writeUInt8(0xFF) // OS = unknown
        if flags & 0x04 != 0 {
            out.writeUInt16(extraLenOverride ?? UInt16(extra.count))
            out.writeBytes(extra)
        }
        if flags & 0x08 != 0 { out.writeBytes(fname) }
        if flags & 0x10 != 0 { out.writeBytes(fcomment) }
        if flags & 0x02 != 0 { out.writeBytes(hcrc) }
        out.writeBytes(payload)
        if let trailer {
            out.writeBytes(trailer)
        } else {
            out.writeUInt32(CRC32.checksum(inflated))
            out.writeUInt32(UInt32(truncatingIfNeeded: inflated.count))
        }
        return out.data
    }

    private func assertMalformed(_ data: Data, _ message: String) {
        XCTAssertThrowsError(try Gzip.decompress(data), message) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData, message)
        }
    }

    /// Wrong magic bytes — including the byte-swapped pair — are rejected
    /// before anything else is read.
    func testWrongMagicRejected() throws {
        let payload = try rawDeflate(of: Self.sample)
        assertMalformed(container(magic: [0x1F, 0x8C], payload: payload, inflated: Self.sample), "second magic byte")
        assertMalformed(container(magic: [0x8B, 0x1F], payload: payload, inflated: Self.sample), "swapped magic")
    }

    /// CM other than 8 (deflate) is unsupported by RFC 1952 §2.3.1.
    func testUnsupportedCompressionMethodRejected() throws {
        let payload = try rawDeflate(of: Self.sample)
        for cm: UInt8 in [0x00, 0x07, 0x09] {
            assertMalformed(container(cm: cm, payload: payload, inflated: Self.sample), "CM \(cm)")
        }
    }

    /// RFC 1952 §2.3.1: FLG bits 5-7 are reserved and must be zero — each is
    /// rejected as malformed instead of being silently ignored. (No compliant
    /// writer sets them, so no real file is affected.)
    func testReservedFlagBitsRejected() throws {
        let payload = try rawDeflate(of: Self.sample)
        for flag: UInt8 in [0x20, 0x40, 0x80] {
            assertMalformed(container(flags: flag, payload: payload, inflated: Self.sample), "reserved FLG \(flag)")
        }
    }

    /// FTEXT is informational (RFC 1952 §2.3.1) and must stay accepted.
    func testFTextFlagAccepted() throws {
        let payload = try rawDeflate(of: Self.sample)
        let gzip = container(flags: 0x01, payload: payload, inflated: Self.sample)
        XCTAssertEqual(try Gzip.decompress(gzip), Self.sample)
    }

    /// Well-formed FEXTRA + FNAME + FCOMMENT + FHCRC fields all parse: the
    /// decoder walks RFC 1952 §2.2 field order and still recovers the payload.
    func testAllOptionalHeaderFieldsAccepted() throws {
        let payload = try rawDeflate(of: Self.sample)
        let gzip = container(
            flags: 0x04 | 0x08 | 0x10 | 0x02,
            extra: Data([0xAA, 0xBB, 0xCC, 0xDD]),
            fname: Data("name.kdbx\0".utf8),
            fcomment: Data("comment\0".utf8),
            hcrc: Data([0x12, 0x34]),
            payload: payload,
            inflated: Self.sample
        )
        XCTAssertEqual(try Gzip.decompress(gzip), Self.sample)
    }

    /// Truncating the container at every byte of the fixed header and each
    /// optional field fails typed — the field walk is bounds-checked at every
    /// step and never reads past the buffer.
    func testHeaderTruncatedAtEveryFieldPositionRejected() throws {
        let payload = try rawDeflate(of: Self.sample)
        let flags: UInt8 = 0x04 | 0x08 | 0x10 | 0x02
        let full = container(
            flags: flags,
            extra: Data([0xAA, 0xBB, 0xCC, 0xDD]),
            fname: Data("name.kdbx".utf8),
            fcomment: Data("comment".utf8),
            hcrc: Data([0x12, 0x34]),
            payload: payload,
            inflated: Self.sample
        )
        // Fixed header (10 B) + FEXTRA (2+4) + FNAME (9+1) + FCOMMENT (7+1) + FHCRC (2).
        let headerEnd = 10 + 6 + 10 + 8 + 2
        XCTAssertLessThan(headerEnd, full.count)
        for cut in 0..<headerEnd {
            assertMalformed(full.prefix(cut), "header cut at \(cut)")
        }
    }

    /// Optional fields that lie about their extent are rejected: an FEXTRA
    /// length beyond the buffer, and unterminated FNAME/FCOMMENT strings.
    func testMalformedOptionalFieldsRejected() throws {
        let payload = try rawDeflate(of: Self.sample)

        // FEXTRA declaring 64 bytes with only 4 present.
        assertMalformed(container(
            flags: 0x04,
            extra: Data([0xAA, 0xBB, 0xCC, 0xDD]),
            extraLenOverride: 64,
            payload: payload,
            inflated: Self.sample
        ), "FEXTRA overlong")

        // Unterminated FNAME (no zero byte before the payload).
        assertMalformed(container(flags: 0x08, fname: Data("never-terminated".utf8), payload: payload, inflated: Self.sample), "FNAME unterminated")
        // Unterminated FCOMMENT.
        assertMalformed(container(flags: 0x10, fcomment: Data("never-terminated".utf8), payload: payload, inflated: Self.sample), "FCOMMENT unterminated")
        // FHCRC with a single byte.
        assertMalformed(container(flags: 0x02, hcrc: Data([0x12]), payload: payload, inflated: Self.sample), "FHCRC short")
    }

    /// The CRC-32/ISIZE trailer is mandatory: cutting 1-7 bytes off the end
    /// fails typed before inflation output is trusted. (Cut at exactly the
    /// payload end leaves 0 trailer bytes; the full container is the 8-byte
    /// control case proven by the round-trip tests.)
    func testTruncatedTrailerRejected() throws {
        let payload = try rawDeflate(of: Self.sample)
        let full = container(payload: payload, inflated: Self.sample)
        for missing in 1...7 {
            assertMalformed(full.prefix(full.count - missing), "trailer missing \(missing)")
        }
    }

    /// A stored (BTYPE=00) block whose NLEN is not the one's complement of
    /// LEN violates RFC 1951 §3.2.4 — zlib's inflate rejects it as "invalid
    /// stored block lengths". Apple's raw-DEFLATE decoder is more lenient and
    /// recovers the block anyway; this is pinned so the platform tolerance is
    /// explicit rather than accidental. Output integrity does not depend on
    /// the decoder's strictness: every recovered byte must still match the
    /// CRC-32/ISIZE trailer, and the whole path is post-authentication — so
    /// closing the gap would mean a hand-rolled DEFLATE pre-validator, which
    /// is not justified for a trailer-verified, credential-gated stream.
    func testStoredBlockComplementCorruptionIsPlatformTolerated() throws {
        var block = ByteWriter()
        block.writeUInt8(0x01) // BFINAL=1, BTYPE=00, padding to byte boundary
        block.writeUInt16(4) // LEN
        block.writeUInt16(4) // NLEN — must be ~LEN (0xFFFB); violation
        block.writeBytes(Data("ABCD".utf8))
        let gzip = container(payload: block.data, trailer: {
            var t = ByteWriter()
            t.writeUInt32(CRC32.checksum(Data("ABCD".utf8)))
            t.writeUInt32(4)
            return t.data
        }())
        XCTAssertEqual(try Gzip.decompress(gzip), Data("ABCD".utf8))
    }

    /// A DEFLATE body truncated inside its data-bearing bytes fails typed —
    /// either the decoder rejects the incomplete stream or the output no
    /// longer matches the CRC-32/ISIZE trailer. (The sweep deliberately stops
    /// short of the tail: a DEFLATE stream is bit-packed and its final byte
    /// can carry only end-of-stream padding bits, so dropping that byte alone
    /// decodes to identical output — an undetectable, harmless truncation
    /// whose result is still trailer-verified.)
    func testTruncatedDeflatePayloadRejected() throws {
        let payload = try rawDeflate(of: Self.sample)
        for keep in 1...(payload.count / 2) {
            assertMalformed(container(payload: payload.prefix(keep), inflated: Self.sample), "payload kept \(keep) of \(payload.count)")
        }
    }
}
