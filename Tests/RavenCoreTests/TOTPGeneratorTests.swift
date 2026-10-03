import XCTest
@testable import RavenCore

/// TOTPGenerator tests (06-02, 06-CONTEXT D-06): the RFC 6238 Appendix B
/// vectors are the oracle — no hand-computed shortcuts. Task 1 pins the
/// SHA-1 column plus truncation/validation; Task 2 completes the full
/// 18-row table with the SHA-256 and SHA-512 columns.
final class TOTPGeneratorTests: XCTestCase {

    /// RFC 6238 Appendix B seeds: the ASCII numeral string "1234567890…"
    /// repeated to the hash's block length (20 bytes for SHA-1, 32 for
    /// SHA-256, 64 for SHA-512).
    private static let sha1Seed = Array("12345678901234567890".utf8)

    /// The SHA-1 column, verbatim from RFC 6238 Appendix B (8-digit).
    private static let sha1Vectors: [(time: TimeInterval, code: String)] = [
        (59, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ]

    /// The SHA-256 column, verbatim (32-byte seed).
    private static let sha256Seed = Array("12345678901234567890123456789012".utf8)
    private static let sha256Vectors: [(time: TimeInterval, code: String)] = [
        (59, "46119246"),
        (1_111_111_109, "68084774"),
        (1_111_111_111, "67062674"),
        (1_234_567_890, "91819424"),
        (2_000_000_000, "90698825"),
        (20_000_000_000, "77737706"),
    ]

    /// The SHA-512 column, verbatim (64-byte seed — the ASCII numeral
    /// string truncated to 64 characters, per RFC 6238 Appendix B).
    private static let sha512Seed = Array(
        "1234567890123456789012345678901234567890123456789012345678901234".utf8)
    private static let sha512Vectors: [(time: TimeInterval, code: String)] = [
        (59, "90693936"),
        (1_111_111_109, "25091201"),
        (1_111_111_111, "99943326"),
        (1_234_567_890, "93441116"),
        (2_000_000_000, "38618901"),
        (20_000_000_000, "47863826"),
    ]

    // MARK: - RFC 6238 Appendix B (SHA-1 column)

    func testSHA1AppendixBVectors() throws {
        for (time, expected) in Self.sha1Vectors {
            let code = try TOTPGenerator.code(
                secret: Self.sha1Seed,
                algorithm: .sha1,
                digits: 8,
                period: 30,
                at: { Date(timeIntervalSince1970: time) })
            XCTAssertEqual(code, expected, "t=\(time) must match the RFC vector byte-exact")
        }
    }

    func testSixDigitTruncation() throws {
        // The 6-digit code is the same 31-bit truncation taken mod 10^6 —
        // the last six digits of the 8-digit vector.
        let code = try TOTPGenerator.code(
            secret: Self.sha1Seed,
            algorithm: .sha1,
            digits: 6,
            period: 30,
            at: { Date(timeIntervalSince1970: 59) })
        XCTAssertEqual(code, "287082")
    }

    // MARK: - RFC 6238 Appendix B (SHA-256 and SHA-512 columns)

    func testSHA256AppendixBVectors() throws {
        for (time, expected) in Self.sha256Vectors {
            let code = try TOTPGenerator.code(
                secret: Self.sha256Seed,
                algorithm: .sha256,
                digits: 8,
                period: 30,
                at: { Date(timeIntervalSince1970: time) })
            XCTAssertEqual(code, expected, "t=\(time) must match the RFC vector byte-exact")
        }
    }

    func testSHA512AppendixBVectors() throws {
        for (time, expected) in Self.sha512Vectors {
            let code = try TOTPGenerator.code(
                secret: Self.sha512Seed,
                algorithm: .sha512,
                digits: 8,
                period: 30,
                at: { Date(timeIntervalSince1970: time) })
            XCTAssertEqual(code, expected, "t=\(time) must match the RFC vector byte-exact")
        }
    }

    // MARK: - Defaults and parameter validation

    func testDefaultsMatchRFC() {
        XCTAssertEqual(TOTPGenerator.defaultPeriod, 30, "RFC 6238 §4.1/§5.2 step")
        XCTAssertEqual(TOTPGenerator.defaultDigits, 6, "RFC 6238 §5.1")
        XCTAssertEqual(
            TOTPGenerator.Algorithm.allCases.map(\.rawValue),
            ["SHA1", "SHA256", "SHA512"],
            "raw values are the otpauth algorithm spellings")
    }

    func testInvalidDigitsThrow() {
        for digits in [5, 7, 0, 12] {
            XCTAssertThrowsError(
                try TOTPGenerator.code(
                    secret: Self.sha1Seed, algorithm: .sha1, digits: digits,
                    period: 30, at: { Date(timeIntervalSince1970: 0) })
            ) { error in
                XCTAssertEqual(error as? TOTPGenerator.TOTPError, .invalidDigits, "digits=\(digits)")
            }
        }
    }

    func testInvalidPeriodThrows() {
        for period in [0, -30] {
            XCTAssertThrowsError(
                try TOTPGenerator.code(
                    secret: Self.sha1Seed, algorithm: .sha1, digits: 6,
                    period: period, at: { Date(timeIntervalSince1970: 0) })
            ) { error in
                XCTAssertEqual(error as? TOTPGenerator.TOTPError, .invalidPeriod, "period=\(period)")
            }
        }
    }

    // MARK: - Period math (the same math the E17/E24 countdown bars drive)

    func testCounterWindowsUseFloor() throws {
        func code(at time: TimeInterval) throws -> String {
            try TOTPGenerator.code(
                secret: Self.sha1Seed, algorithm: .sha1, digits: 8, period: 30,
                at: { Date(timeIntervalSince1970: time) })
        }
        XCTAssertEqual(try code(at: 0), try code(at: 29), "same window ⇒ same code")
        XCTAssertEqual(try code(at: 30), "94287082", "t=30 opens the window whose t=59 vector is pinned")
        XCTAssertNotEqual(try code(at: 29), try code(at: 30), "the window boundary rolls the counter")
    }

    func testSecondsRemaining() {
        XCTAssertEqual(TOTPGenerator.secondsRemaining(period: 30, at: Date(timeIntervalSince1970: 0)), 30)
        XCTAssertEqual(TOTPGenerator.secondsRemaining(period: 30, at: Date(timeIntervalSince1970: 59)), 1)
        XCTAssertEqual(TOTPGenerator.secondsRemaining(period: 30, at: Date(timeIntervalSince1970: 60)), 30)
        XCTAssertEqual(TOTPGenerator.secondsRemaining(period: 60, at: Date(timeIntervalSince1970: 59)), 1)
    }
}
