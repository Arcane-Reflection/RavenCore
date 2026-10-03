import CryptoKit
import XCTest
@testable import RavenCore

/// WebAuthn engine builders (06-CONTEXT D-10, plan Task 2 behaviors):
/// authenticator-data layout, COSE EC2 P-256 encoding, canonical CBOR,
/// ES256 assertion against an independently verified signature, and
/// deterministic registration builds. Flag truthfulness (T-06-14) is
/// asserted against explicit inputs — no code path may derive UV/BE/BS
/// from constants.
final class WebAuthnTests: XCTestCase {

    // MARK: - Fixtures

    /// A fresh stored credential with a REAL P-256 key so the signature
    /// verifies cryptographically.
    private func makeCredential(
        rpID: String = "example.com",
        isUserVerified flagInputs: (Bool, Bool, Bool) = (true, true, false)
    ) throws -> PasskeyCredential {
        let key = P256.Signing.PrivateKey()
        return PasskeyCredential(
            username: "alice@example.com",
            rpID: rpID,
            credentialID: KdbxPasskey.base64URLEncode(Data(repeating: 0xAB, count: 32)),
            userHandle: KdbxPasskey.base64URLEncode(Data(repeating: 0xCD, count: 32)),
            privateKeyPEM: key.pemRepresentation,
            backupEligibility: flagInputs.1,
            backupState: flagInputs.2)
    }

    private func privateKey(of credential: PasskeyCredential) throws -> P256.Signing.PrivateKey {
        try P256.Signing.PrivateKey(pemRepresentation: credential.privateKeyPEM)
    }

    /// Big-endian byte form of a fixed-width integer (mirrors the builders).
    private func bigEndianBytes<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }

    // MARK: - Authenticator data layout (byte-exact)

    func testAssertionLayoutIsByteExact() throws {
        let rpID = "example.com"
        let expectedHash = Data(SHA256.hash(data: Data(rpID.utf8)))
        // UP | UV | BE (no BS) with signCount 0x0102A364.
        let flags = AuthenticatorData.Flags(
            isUserVerified: true, backupEligibility: true, backupState: false)

        let data = try AuthenticatorData.assertion(
            rpID: rpID, signCount: 0x0102A364, flags: flags)

        var expected = expectedHash
        expected.append(0x01 | 0x04 | 0x08) // UP | UV | BE
        expected.append(contentsOf: bigEndianBytes(UInt32(0x0102A364)))
        XCTAssertEqual(data, expected)
        XCTAssertEqual(data.count, 32 + 1 + 4)    }

    func testFlagByteCompositionMatrix() throws {
        // UP is always set; UV/BE/BS appear only from their explicit inputs.
        let cases: [(Bool, Bool, Bool, UInt8)] = [
            (false, false, false, 0x01),
            (true, false, false, 0x01 | 0x04),
            (false, true, false, 0x01 | 0x08),
            (false, false, true, 0x01 | 0x10),
            (true, true, true, 0x01 | 0x04 | 0x08 | 0x10),
        ]
        for (uv, be, bs, byte) in cases {
            let flags = AuthenticatorData.Flags(
                isUserVerified: uv, backupEligibility: be, backupState: bs)
            XCTAssertEqual(flags.byte, byte, "uv=\(uv) be=\(be) bs=\(bs)")
        }
    }

    func testRegistrationLayoutIsByteExact() throws {
        let rpID = "example.com"
        let credentialID = Data(repeating: 0x11, count: 32)
        let coseKey = Data([0xA5, 0x01, 0x02, 0x03, 0x26]) // shape only — layout test
        let flags = AuthenticatorData.Flags(
            isUserVerified: true, backupEligibility: true, backupState: true)

        let data = try AuthenticatorData.registration(
            rpID: rpID, signCount: 0, flags: flags,
            credentialID: credentialID, attestedCredentialKey: coseKey)

        var expected = Data(SHA256.hash(data: Data(rpID.utf8)))
        expected.append(0x01 | 0x04 | 0x08 | 0x10 | 0x40) // UP|UV|BE|BS|AT
        expected.append(contentsOf: bigEndianBytes(UInt32(0)))
        expected.append(Data(repeating: 0x00, count: 16)) // AAGUID
        expected.append(contentsOf: bigEndianBytes(UInt16(32)))
        expected.append(credentialID)
        expected.append(coseKey)
        XCTAssertEqual(data, expected)
    }

    func testEmptyRelyingPartyThrowsExactCase() {
        XCTAssertThrowsError(try AuthenticatorData.rpIdHash("")) { error in
            XCTAssertEqual(error as? WebAuthnError, .emptyRelyingParty)
        }
    }

    func testOverlongCredentialIDThrowsExactCase() {
        let flags = AuthenticatorData.Flags(
            isUserVerified: true, backupEligibility: true, backupState: true)
        XCTAssertThrowsError(
            try AuthenticatorData.registration(
                rpID: "example.com", signCount: 0, flags: flags,
                credentialID: Data(repeating: 0x00, count: 1024),
                attestedCredentialKey: Data())
        ) { error in
            XCTAssertEqual(error as? WebAuthnError, .credentialIDTooLong)
        }
    }

    // MARK: - COSE key

    func testCOSEKeyEC2P256CanonicalByteLayout() throws {
        let key = P256.Signing.PrivateKey()
        let raw = key.publicKey.rawRepresentation
        let x = raw.dropFirst().prefix(32)
        let y = raw.dropFirst().suffix(32)

        let encoded = COSEKey.ec2P256(key.publicKey)

        // 0xA5 (5-entry map) 01 02 (kty: 2) 03 26 (alg: -7) 20 01 (crv: 1)
        // 21 58 20 <x> 22 58 20 <y> — canonical bytewise key order.
        var expected = Data([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
        expected.append(x)
        expected.append(contentsOf: [0x22, 0x58, 0x20])
        expected.append(y)
        XCTAssertEqual(encoded, expected)
    }

    // MARK: - CBOR

    func testCBORAttestationObjectCanonicalForm() throws {
        let authData = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let object = CBOR.encode(.map([
            (.text("fmt"), .text("none")),
            (.text("attStmt"), .map([])),
            (.text("authData"), .byteString(authData)),
        ]))

        // RFC 8949 §4.2.1 canonical order sorts by ENCODED key bytes —
        // shorter keys first, so `fmt` (0x63…) < `attStmt` (0x67…) <
        // `authData` (0x68…). This is the CTAP2 canonical form; relying
        // parties parse CBOR maps unordered either way.
        var expected = Data([0xA3])
        expected.append(0x63) // text(3)
        expected.append(Data("fmt".utf8))
        expected.append(0x64) // text(4)
        expected.append(Data("none".utf8))
        expected.append(contentsOf: [0x67]) // text(7)
        expected.append(Data("attStmt".utf8))
        expected.append(0xA0) // empty map
        expected.append(0x68) // text(8)
        expected.append(Data("authData".utf8))
        expected.append(contentsOf: [0x44, 0xDE, 0xAD, 0xBE, 0xEF]) // bytes(4)
        XCTAssertEqual(object, expected)
    }

    func testCBORHeadMinimalEncodings() {
        // RFC 8949 Appendix A style spot checks.
        XCTAssertEqual(CBOR.encode(.int(0)), Data([0x00]))
        XCTAssertEqual(CBOR.encode(.int(23)), Data([0x17]))
        XCTAssertEqual(CBOR.encode(.int(24)), Data([0x18, 0x18]))
        XCTAssertEqual(CBOR.encode(.int(255)), Data([0x18, 0xFF]))
        XCTAssertEqual(CBOR.encode(.int(256)), Data([0x19, 0x01, 0x00]))
        XCTAssertEqual(CBOR.encode(.int(-7)), Data([0x26]))
        XCTAssertEqual(CBOR.encode(.int(-1)), Data([0x20]))
        XCTAssertEqual(CBOR.encode(.text("a")), Data([0x61, 0x61]))
    }

    // MARK: - Assertion (ES256, independently verified)

    func testAssertionSignatureVerifiesIndependently() throws {
        let credential = try makeCredential()
        let key = try privateKey(of: credential)
        let clientDataHash = Data(SHA256.hash(data: Data("{\"challenge\":\"abc\"}".utf8)))

        let output = try PasskeyAssertion.build(
            credential: credential,
            clientDataHash: clientDataHash,
            isUserVerified: true)

        // The signature verifies over authData ‖ clientDataHash with the
        // credential's own public key — an independent cryptographic check,
        // not a byte echo of the builder output.
        let signature = try XCTUnwrap(try? P256.Signing.ECDSASignature(
            derRepresentation: output.signature))
        XCTAssertTrue(
            key.publicKey.isValidSignature(signature, for: output.authenticatorData + clientDataHash),
            "ES256 signature must verify over authenticatorData ‖ clientDataHash")

        // The rpIdHash binds to the STORED rpID (key_links requirement).
        let expectedHash = Data(SHA256.hash(data: Data(credential.rpID.utf8)))
        XCTAssertEqual(output.authenticatorData.prefix(32), expectedHash)
        // UP|UV|BE set; BS clear (fixture stores backupState false).
        XCTAssertEqual(output.authenticatorData[32], 0x01 | 0x04 | 0x08)
    }

    func testAssertionFlagsDeriveOnlyFromStoredStateAndInputs() throws {
        let clientDataHash = Data([0x01, 0x02])
        // Stored BS = false must stay false even when UV is requested.
        let credential = try makeCredential()
        let output = try PasskeyAssertion.build(
            credential: credential, clientDataHash: clientDataHash, isUserVerified: true)
        XCTAssertEqual(output.authenticatorData[32], 0x01 | 0x04 | 0x08, "no fabricated BS bit")

        // Without UV in this request, the UV bit must be clear.
        let noUV = try PasskeyAssertion.build(
            credential: credential, clientDataHash: clientDataHash, isUserVerified: false)
        XCTAssertEqual(noUV.authenticatorData[32], 0x01 | 0x08, "UV only when actually performed")
    }

    func testMalformedPEMThrowsExactCaseWithoutSigning() throws {
        var credential = try makeCredential()
        credential.privateKeyPEM = "not a pem"
        XCTAssertThrowsError(try PasskeyAssertion.build(
            credential: credential,
            clientDataHash: Data([0x00]),
            isUserVerified: true)) { error in
            XCTAssertEqual(error as? WebAuthnError, .privateKeyConversionFailed)
        }
    }

    // MARK: - Registration (deterministic via the random seam)

    func testRegistrationBuildIsDeterministicFromSeededRandom() throws {
        let seed: [(Int) -> Data] = [
            { _ in Data(repeating: 0x11, count: 32) }, // credentialID
            { _ in Data(repeating: 0x22, count: 32) }, // userHandle
        ]
        var callIndex = 0
        let clientDataHash = Data(SHA256.hash(data: Data("register".utf8)))

        let material = try PasskeyRegistration.build(
            rpID: "example.com",
            clientDataHash: clientDataHash,
            isUserVerified: true,
            random: { count in
                let value = seed[callIndex % seed.count](count)
                callIndex += 1
                return value
            })

        XCTAssertEqual(material.credentialID, Data(repeating: 0x11, count: 32))
        XCTAssertEqual(material.userHandle, Data(repeating: 0x22, count: 32))
        XCTAssertTrue(material.privateKeyPEM.contains("BEGIN PRIVATE KEY"))
        XCTAssertEqual(material.privateKeyPEM.contains("END PRIVATE KEY"), true)

        // The attestation object carries fmt "none" and the exact authData.
        XCTAssertTrue(material.attestationObject.contains(Data("none".utf8)))
        XCTAssertTrue(material.attestationObject.contains(material.authenticatorData))

        // Attested credential data: AAGUID 16×0x00, credIdLen, credentialID.
        let attested = material.authenticatorData.dropFirst(32 + 1 + 4)
        XCTAssertEqual(attested.prefix(16), Data(repeating: 0x00, count: 16))
        let length = attested.dropFirst(16).prefix(2)
        XCTAssertEqual(length, Data([0x00, 0x20]), "2-byte big-endian credential ID length")
        XCTAssertEqual(attested.dropFirst(18).prefix(32), material.credentialID)
        // AT flag set; UP|UV|BE|BS present.
        XCTAssertEqual(material.authenticatorData[32], 0x01 | 0x04 | 0x08 | 0x10 | 0x40)
    }

    func testRegistrationKeyPairMatchesStoredPEM() throws {
        let material = try PasskeyRegistration.build(
            rpID: "example.com",
            clientDataHash: Data([0x03]),
            isUserVerified: false,
            random: { count in SecureRandom.bytes(count: count) })

        // The stored PEM must reopen to a P-256 key whose public key encodes
        // to exactly the COSE key embedded in the authenticator data.
        let key = try P256.Signing.PrivateKey(pemRepresentation: material.privateKeyPEM)
        let cose = COSEKey.ec2P256(key.publicKey)
        XCTAssertTrue(material.authenticatorData.suffix(cose.count).elementsEqual(cose),
                      "attested credential data must end with the COSE EC2 key")
    }

    // MARK: - base64url codec round trip

    func testBase64URLDecodeRoundTrips() {
        let bytes = Data([0xFB, 0xEF, 0xBE, 0xFF, 0x01])
        XCTAssertEqual(KdbxPasskey.base64URLDecode(KdbxPasskey.base64URLEncode(bytes)), bytes)
        XCTAssertNil(KdbxPasskey.base64URLDecode("!!not-base64!!"))
    }
}
