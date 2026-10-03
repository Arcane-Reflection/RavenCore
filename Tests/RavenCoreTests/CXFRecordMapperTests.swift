import CryptoKit
import XCTest
@testable import RavenCore

/// CXF → RecordPayload mapping (06-03 Task 3, D-11): the committed
/// `cxf-sample.json` fixture — authored against the CXF wire shape pinned
/// from the real `ASExportedCredentialData` Codable implementation — decodes
/// through the typed mirror decoder (`.secondsSince1970` strategy) and maps
/// into RecordPayloads with an honest Added/Skipped report. Unsupported
/// kinds and the malformed passkey are NAMED skips; nothing aborts the
/// batch; decode failure is the typed all-or-nothing path.
final class CXFRecordMapperTests: XCTestCase {

    /// The committed fixture, decoded through the mapper's typed decoder
    /// (same repo-relative fixture access as `RecordPayloadPasskeyTests`).
    private func decodeFixture() throws -> [CXFRecordMapper.SourceAccount] {
        let url = URL(fileURLWithPath: TestFixtures.packageRoot)
            .appendingPathComponent("Tests/Fixtures/cxf-sample.json")
        let data = try Data(contentsOf: url)
        return try CXFRecordMapper.decode(data)
    }

    // MARK: - Decode (typed, local, secondsSince1970)

    func testDecodeReadsPinnedWireShape() throws {
        let accounts = try decodeFixture()

        XCTAssertEqual(accounts.count, 1)
        XCTAssertEqual(accounts[0].userName, "otter@example.com")
        XCTAssertEqual(accounts[0].items.count, 5, "all four kinds + the malformed passkey item")
    }

    func testDecodeRejectsGarbagePayloadTyped() {
        XCTAssertThrowsError(try CXFRecordMapper.decode(Data("not json".utf8))) { error in
            XCTAssertEqual(error as? CXFRecordMapper.CXFDecodeError, .malformedPayload)
        }
    }

    // MARK: - Map: the fixture's honest report

    func testFixtureMapsToExpectedEntriesAndNamedSkips() throws {
        let report = CXFRecordMapper.map(accounts: try decodeFixture())

        XCTAssertEqual(report.added.count, 2,
                       "the password spine (with its attached totpSecret) and the passkey record")
        XCTAssertEqual(report.skipped.count, 3)
        XCTAssertEqual(
            Set(report.skipped.map(\.reason)),
            ["unsupported.note", "unsupported.credit-card", "unreadablePasskey"],
            "every loss is named — skips are never silent (E14)")
    }

    func testBasicAuthAndAttachedTOTPMapToThePasswordSpine() throws {
        let report = CXFRecordMapper.map(accounts: try decodeFixture())

        let spine = try XCTUnwrap(
            report.added.first { $0.type == .password && $0.payload.title == "Example" })
        XCTAssertEqual(spine.payload.username, "otter@example.com")
        XCTAssertEqual(spine.payload.password, "hunter2")
        XCTAssertEqual(spine.payload.url, "https://example.com/login")
        // D-07 verbatim semantics: non-default parameters ⇒ composed URI.
        let stored = try XCTUnwrap(spine.payload.totpSecret)
        XCTAssertTrue(stored.hasPrefix("otpauth://totp/"), stored)
        XCTAssertTrue(stored.contains("secret=AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQT"))
        XCTAssertTrue(stored.contains("issuer=Example"))
        XCTAssertTrue(stored.contains("algorithm=SHA256"))
        XCTAssertTrue(stored.contains("digits=8"))
        XCTAssertTrue(stored.contains("period=60"))
        // The stored URI parses back through the 06-02 parser with the same
        // generation parameters (the CXF extraction contract).
        let parameters = try XCTUnwrap(OTPAuthURIParser.parse(stored))
        XCTAssertEqual(parameters.algorithm, .sha256)
        XCTAssertEqual(parameters.digits, 8)
        XCTAssertEqual(parameters.period, 60)
    }

    func testPasskeyMapsIntoTaskOneFieldKeePassXCCompatible() throws {
        let report = CXFRecordMapper.map(accounts: try decodeFixture())

        let entry = try XCTUnwrap(
            report.added.first { $0.payload.title == "Passkey Example" })
        let credential = try XCTUnwrap(entry.payload.passkey,
                                       "the passkey rides Task 1's RecordPayload.passkey")
        XCTAssertEqual(credential.rpID, "passkey.example.com")
        XCTAssertEqual(credential.username, "otter@example.com")
        XCTAssertEqual(
            credential.credentialID,
            KdbxPasskey.base64URLEncode(Data((0..<32).map { UInt8($0) })),
            "KPEX_PASSKEY_CREDENTIAL_ID is base64url of the wire bytes, stored verbatim")
        XCTAssertEqual(
            credential.userHandle,
            KdbxPasskey.base64URLEncode(Data((32..<64).map { UInt8($0) })))
        XCTAssertTrue(credential.privateKeyPEM.contains("BEGIN PRIVATE KEY"))
        XCTAssertEqual(credential.backupEligibility, true)
        XCTAssertEqual(credential.backupState, true)
        // The PEM re-opens to the SAME public key the wire bytes carried —
        // the x9.63 conversion preserved the key identity (the fixture's
        // committed key bytes, base64 → x9.63).
        let wireKey = try P256.Signing.PrivateKey(x963Representation: Data(base64Encoded:
            "BPhTLYMVe1CKOuBtj3g5x6OwxYKSBhLQnLc5CK++JFG9OG0+qoug0rwhH7Jk1QsHqcne3OB0VZWKk5AYXDp/1NsudZC0UvgifDjPxJsLp2n5fafeDIa76ZXiL9FFjfb2fw==")!)
        let reopened = try P256.Signing.PrivateKey(pemRepresentation: credential.privateKeyPEM)
        XCTAssertEqual(
            Data(reopened.publicKey.x963Representation),
            Data(wireKey.publicKey.x963Representation))
    }

    // MARK: - totpSecret composition rules (D-07 verbatim)

    func testDefaultParametersStoreBareSecret() {
        let secret = Data([0x01, 0x02, 0x03, 0x04])
        let stored = CXFRecordMapper.totpSecret(
            secret: secret, period: 30, digits: 6,
            userName: "otter", algorithm: "sha1", issuer: nil)
        XCTAssertEqual(stored, Base32.encode([UInt8](secret)),
                       "RFC defaults + no issuer ⇒ bare base32 secret")
        XCTAssertEqual(OTPAuthURIParser.secret(in: stored ?? ""), "AEBAGBA")
    }

    func testUnknownAlgorithmOrEmptySecretIsNil() {
        XCTAssertNil(CXFRecordMapper.totpSecret(
            secret: Data([0x01]), period: 30, digits: 6,
            userName: "otter", algorithm: "sm3", issuer: nil))
        XCTAssertNil(CXFRecordMapper.totpSecret(
            secret: Data(), period: 30, digits: 6,
            userName: "otter", algorithm: "sha1", issuer: nil))
    }

    // MARK: - Empty / edge inputs

    func testEmptyTransferProducesAnHonestEmptyReport() {
        let report = CXFRecordMapper.map(accounts: [])
        XCTAssertEqual(report.added, [])
        XCTAssertEqual(report.skipped, [])
    }

    func testItemWithoutCredentialsIsANamedSkip() {
        let report = CXFRecordMapper.map(accounts: [
            .init(userName: "otter", items: [
                .init(title: "Empty", credentials: []),
            ]),
        ])
        XCTAssertEqual(report.added, [])
        XCTAssertEqual(report.skipped.map(\.reason), ["empty"])
    }

    func testEmptyBasicAuthIsANamedSkip() {
        let report = CXFRecordMapper.map(accounts: [
            .init(userName: "otter", items: [
                .init(title: "Blank", credentials: [
                    .basicAuthentication(userName: "", password: ""),
                ]),
            ]),
        ])
        XCTAssertEqual(report.added, [])
        XCTAssertEqual(report.skipped.map(\.reason), ["empty"])
    }

    // MARK: - Duplicate sibling TOTP (06 review WR-03: named loss, never a
    // silent overwrite)

    private func sampleTOTP(_ byte: UInt8, algorithm: String = "sha1") -> CXFRecordMapper.SourceCredential {
        .totp(
            secret: Data([byte]), period: 30, digits: 6,
            userName: "otter", algorithm: algorithm, issuer: nil)
    }

    func testSecondSiblingTOTPIsANamedDuplicateSkipNotAnOverwrite() {
        let report = CXFRecordMapper.map(accounts: [
            .init(userName: "otter", items: [
                .init(title: "Spine", credentials: [
                    .basicAuthentication(userName: "otter", password: "pw"),
                    sampleTOTP(0x01),
                    sampleTOTP(0x02),
                ]),
            ]),
        ])

        XCTAssertEqual(report.added.count, 1, "the spine is the only added record")
        XCTAssertEqual(report.skipped.map(\.reason), ["duplicateTotp"],
                       "the second sibling TOTP is named, never silently dropped or overwritten (E14/WR-03)")
        // The FIRST attached secret survives verbatim.
        XCTAssertEqual(
            report.added[0].payload.totpSecret,
            Base32.encode([0x01]),
            "the spine carries the first sibling's secret — order is stable, no overwrite")
    }

    /// Order independence (fifth-pass follow-up): a TOTP credential BEFORE
    /// the item's password used to become a standalone record plus a bare
    /// password — the same manifest imported differently by array order.
    /// Both orders must now produce the identical combined record.
    func testTOTPBeforePasswordAttachesToTheSpine() {
        func map(_ credentials: [CXFRecordMapper.SourceCredential]) -> CXFRecordMapper.Report {
            CXFRecordMapper.map(accounts: [
                .init(userName: "otter", items: [
                    .init(title: "Spine", credentials: credentials),
                ]),
            ])
        }

        let totpFirst = map([sampleTOTP(0x01), .basicAuthentication(userName: "otter", password: "pw")])
        let basicFirst = map([.basicAuthentication(userName: "otter", password: "pw"), sampleTOTP(0x01)])

        XCTAssertEqual(totpFirst.added, basicFirst.added,
                       "credential array order must not change the import result")
        XCTAssertEqual(totpFirst.skipped, basicFirst.skipped)
        XCTAssertEqual(totpFirst.added.count, 1)
        XCTAssertEqual(totpFirst.added[0].type, .password)
        XCTAssertEqual(totpFirst.added[0].payload.totpSecret, Base32.encode([0x01]))
    }

    func testSpinelessTOTPsStillBecomeSeparateRecords() {
        let report = CXFRecordMapper.map(accounts: [
            .init(userName: "otter", items: [
                .init(title: "Codes", credentials: [
                    sampleTOTP(0x01),
                    sampleTOTP(0x02),
                ]),
            ]),
        ])

        XCTAssertEqual(report.added.count, 2,
                       "without a spine each TOTP is its own record — no duplicate interaction")
        XCTAssertEqual(report.skipped, [])
        XCTAssertEqual(report.added[0].payload.totpSecret, Base32.encode([0x01]))
        XCTAssertEqual(report.added[1].payload.totpSecret, Base32.encode([0x02]))
    }
}
