import XCTest
@testable import RavenCore

/// OTPAuthURIParser tests (06-02, 06-CONTEXT D-07): the single parser
/// serving CSV import, kdbx import, code generation, and the E18 edit-field
/// gate. Strict for GENERATION (parameter values fail closed — RESEARCH
/// V5/T-06-11); the `secret(in:)` extraction keeps the import semantics the
/// CSV/kdbx mappers have always had (their existing tests stay unmodified —
/// the hoist is behavior-preserving).
final class OTPAuthURIParserTests: XCTestCase {

    // MARK: - Full parse (generation parameter set)

    func testFullURIParsesAllParameters() throws {
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse(
            "otpauth://totp/Acme:otter@acme.example?secret=GEZDGNBVGY3TQOJQ&issuer=Acme&algorithm=SHA256&digits=8&period=60"))
        XCTAssertEqual(parameters.secret, "GEZDGNBVGY3TQOJQ")
        XCTAssertEqual(parameters.issuer, "Acme", "the issuer parameter wins over the label prefix")
        XCTAssertEqual(parameters.algorithm, .sha256)
        XCTAssertEqual(parameters.digits, 8)
        XCTAssertEqual(parameters.period, 60)
        XCTAssertNil(parameters.counter)
        XCTAssertTrue(parameters.isGeneratable)
    }

    func testIssuerFallsBackToLabelPrefix() throws {
        // "Issuer:account" path component — percent-decoded.
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse(
            "otpauth://totp/Acme%20Corp:otter?secret=GEZDGNBVGY3TQOJQ"))
        XCTAssertEqual(parameters.issuer, "Acme Corp")
    }

    func testMissingParametersDefaultToRFC() throws {
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse(
            "otpauth://totp/otter?secret=GEZDGNBVGY3TQOJQ"))
        XCTAssertEqual(parameters.algorithm, .sha1)
        XCTAssertEqual(parameters.digits, 6)
        XCTAssertEqual(parameters.period, 30)
        XCTAssertNil(parameters.issuer, "no issuer parameter and no label prefix ⇒ no issuer")
    }

    func testParameterNamesMatchCaseInsensitively() throws {
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse(
            "otpauth://totp/x?SECRET=GEZDGNBVGY3TQOJQ&Issuer=Acme&Digits=8&ALGORITHM=SHA512&Period=15"))
        XCTAssertEqual(parameters.secret, "GEZDGNBVGY3TQOJQ")
        XCTAssertEqual(parameters.issuer, "Acme")
        XCTAssertEqual(parameters.algorithm, .sha512)
        XCTAssertEqual(parameters.digits, 8)
        XCTAssertEqual(parameters.period, 15)
    }

    func testBareSecretPassesThroughWithDefaults() throws {
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse("JBSWY3DPEHPK3PXP"))
        XCTAssertEqual(parameters.secret, "JBSWY3DPEHPK3PXP")
        XCTAssertNil(parameters.issuer)
        XCTAssertEqual(parameters.algorithm, .sha1)
        XCTAssertEqual(parameters.digits, 6)
        XCTAssertEqual(parameters.period, 30)
        XCTAssertTrue(parameters.isGeneratable)
    }

    func testSurroundingWhitespaceTrimmed() throws {
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse("  JBSWY3DPEHPK3PXP\n"))
        XCTAssertEqual(parameters.secret, "JBSWY3DPEHPK3PXP")
    }

    // MARK: - Fail-closed (strict generation parse, T-06-11)

    func testMissingSecretFailsClosed() {
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://totp/nosecret?period=30"))
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://totp/x?secret="))
        XCTAssertNil(OTPAuthURIParser.parse("   "))
        XCTAssertNil(OTPAuthURIParser.parse(""))
    }

    func testMalformedParameterValuesFailClosed() {
        // A present-but-invalid value must never silently fall back to the
        // default — the codes would be silently wrong (RESEARCH Pitfall 8).
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://totp/x?secret=ABC&digits=7"))
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://totp/x?secret=ABC&digits=abc"))
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://totp/x?secret=ABC&algorithm=MD5"))
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://totp/x?secret=ABC&period=0"))
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://totp/x?secret=ABC&period=-5"))
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://totp/x?secret=ABC&period=later"))
    }

    func testUnknownTypeFailsClosed() {
        XCTAssertNil(OTPAuthURIParser.parse("otpauth://migration/data?secret=ABC"))
    }

    // MARK: - HOTP (D-07: counter out of scope, period semantics otherwise)

    func testHotpWithCounterRecordedAsNotGeneratable() throws {
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse(
            "otpauth://hotp/x?secret=ABC234&counter=4"))
        XCTAssertEqual(parameters.secret, "ABC234")
        XCTAssertEqual(parameters.counter, 4)
        XCTAssertFalse(parameters.isGeneratable,
                       "counter-based codes are out of scope — never live-generate")
    }

    func testHotpWithoutCounterTreatedWithPeriodSemantics() throws {
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse(
            "otpauth://hotp/x?secret=ABC234"))
        XCTAssertNil(parameters.counter)
        XCTAssertTrue(parameters.isGeneratable)
    }

    // MARK: - secret(in:) — the import-extraction contract (CSV/kdbx)

    /// Mirrors the pre-hoist `VaultCSVMapper.otpauthSecret` behavior — the
    /// existing CsvTests pins must keep passing THROUGH the delegation.
    func testSecretExtractionKeepsImportSemantics() {
        XCTAssertEqual(OTPAuthURIParser.secret(in: "otpauth://totp/acme?secret=ABC234&period=30&digits=8&issuer=Acme"), "ABC234")
        XCTAssertEqual(OTPAuthURIParser.secret(in: "  PLAINSECRET  "), "PLAINSECRET")
        XCTAssertNil(OTPAuthURIParser.secret(in: "otpauth://totp/nosecret?period=30"))
        XCTAssertNil(OTPAuthURIParser.secret(in: "   "))
        // A hotp URI with a counter still yields its secret (import keeps
        // data; generation gates on isGeneratable).
        XCTAssertEqual(OTPAuthURIParser.secret(in: "otpauth://hotp/x?secret=ABC234&counter=4"), "ABC234")
    }
}
