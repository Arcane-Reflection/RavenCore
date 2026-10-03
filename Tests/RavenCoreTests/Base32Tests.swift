import XCTest
@testable import RavenCore

/// Base32 decoder tests (06-02, 06-CONTEXT D-06): RFC 4648 §10.2 vectors
/// plus the tolerance decisions pinned as behavior — case-insensitive,
/// trailing padding tolerated, non-canonical leftover bits tolerated,
/// everything outside the alphabet and every length that cannot encode
/// whole bytes rejected (fail-closed, V5 input-validation posture).
final class Base32Tests: XCTestCase {

    // MARK: - RFC 4648 §10.2 vectors

    func testRFC4648VectorsWithPadding() throws {
        XCTAssertEqual(try Base32.decode(""), [])
        XCTAssertEqual(try Base32.decode("MY======"), Array("f".utf8))
        XCTAssertEqual(try Base32.decode("MZXQ===="), Array("fo".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6==="), Array("foo".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6YQ="), Array("foob".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6YTB"), Array("fooba".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6YTBOI======"), Array("foobar".utf8))
    }

    func testUnpaddedInputAccepted() throws {
        // Padding is tolerated on read, never required — Google
        // Authenticator-style secrets are unpadded.
        XCTAssertEqual(try Base32.decode("MY"), Array("f".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6YQ"), Array("foob".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6YTBOI"), Array("foobar".utf8))
    }

    func testLowercaseAccepted() throws {
        XCTAssertEqual(try Base32.decode("mzxw6ytb"), Array("fooba".utf8))
        XCTAssertEqual(try Base32.decode("mzxw6ytboi"), Array("foobar".utf8))
    }

    /// The canonical Google Authenticator sample secret — the shape real
    /// otpauth/CSV imports carry.
    func testKnownTOTPSecretDecodes() throws {
        // "Hello!" + 0xDE 0xAD 0xBE 0xEF — raw bytes, not UTF-8 of the
        // scalar-escaped string.
        XCTAssertEqual(
            try Base32.decode("JBSWY3DPEHPK3PXP"),
            [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF])
    }

    // MARK: - Reject cases (fail-closed)

    func testInvalidCharacterRejected() {
        // 1/0/8/9 are not in the RFC 4648 Base32 alphabet.
        XCTAssertThrowsError(try Base32.decode("MZ1W6YTB")) { error in
            XCTAssertEqual(error as? Base32.Base32Error, .invalidCharacter)
        }
        // Whitespace is invalid INSIDE the value (callers trim the outer
        // ends before decoding).
        XCTAssertThrowsError(try Base32.decode("MZXW 6YTB")) { error in
            XCTAssertEqual(error as? Base32.Base32Error, .invalidCharacter)
        }
    }

    func testPaddingOnlyToleratedAtTheEnd() {
        XCTAssertThrowsError(try Base32.decode("M=ZXW6YTB")) { error in
            XCTAssertEqual(error as? Base32.Base32Error, .invalidCharacter)
        }
    }

    func testImpossibleLengthsRejected() {
        // Character counts ≡ 1, 3 or 6 (mod 8) cannot encode whole bytes —
        // no well-formed generator emits them.
        for broken in ["A", "ABC", "ABCDEF"] {
            XCTAssertThrowsError(try Base32.decode(broken)) { error in
                XCTAssertEqual(error as? Base32.Base32Error, .invalidLength, broken)
            }
        }
    }

    /// Non-canonical (non-zero) leftover bits are TOLERATED — sloppy
    /// generators exist and import paths feed this decoder; canonicity of
    /// discarded bits is deliberately not enforced.
    func testNonCanonicalLeftoverBitsTolerated() throws {
        XCTAssertEqual(try Base32.decode("AB"), [0x00])
    }
}
