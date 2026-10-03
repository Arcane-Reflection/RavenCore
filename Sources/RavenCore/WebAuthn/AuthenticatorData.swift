import CryptoKit
import Foundation

/// Typed failures of the WebAuthn builders. `Equatable` for exact-case test
/// assertions; plain cases only — never credential material (the Passkey.swift
/// sanctioned-error shape).
public enum WebAuthnError: Error, Equatable {
    /// The relying-party ID is empty — no rpIdHash can be computed.
    case emptyRelyingParty
    /// The credential ID exceeds the 1023-byte attested-credential-data bound.
    case credentialIDTooLong
    /// The stored PEM does not convert to a P-256 signing key at build time.
    case privateKeyConversionFailed
}

/// WebAuthn authenticator-data builders (06-CONTEXT D-10, W3C WebAuthn L2
/// §6.1). Every layout is byte-exact and vector-pinned in `WebAuthnTests`.
///
/// Flag truthfulness is a TYPE-LEVEL constraint (T-06-14): the builders take
/// explicit `Flags` inputs and never infer them — UV is set only when user
/// verification was actually performed in THIS request, and BE/BS carry only
/// the credential's stored backup state. No code path can fabricate a
/// ceremony claim by construction.
public enum AuthenticatorData {

    /// The authenticator-flags inputs, supplied explicitly by the caller
    /// (see the type comment — no inference, ever).
    public struct Flags: Sendable, Equatable {
        /// User verification performed in this request (bit 2, 0x04).
        public let isUserVerified: Bool
        /// Stored backup eligibility (bit 3, 0x08).
        public let backupEligibility: Bool
        /// Stored backup state (bit 4, 0x10).
        public let backupState: Bool

        public init(isUserVerified: Bool, backupEligibility: Bool, backupState: Bool) {
            self.isUserVerified = isUserVerified
            self.backupEligibility = backupEligibility
            self.backupState = backupState
        }

        /// The flag byte: UP (0x01) is always set — an assertion/registration
        /// is only built after the user's presence was confirmed in the
        /// interactive request flow (D-03).
        var byte: UInt8 {
            var value: UInt8 = 0x01
            if isUserVerified { value |= 0x04 }
            if backupEligibility { value |= 0x08 }
            if backupState { value |= 0x10 }
            return value
        }
    }

    /// rpIdHash — SHA-256 over the relying-party ID. Assertions bind to the
    /// STORED credential's rpID, never to a display string (key_links).
    public static func rpIdHash(_ rpID: String) throws -> Data {
        guard !rpID.isEmpty else { throw WebAuthnError.emptyRelyingParty }
        return Data(SHA256.hash(data: Data(rpID.utf8)))
    }

    /// Assertion layout: `rpIdHash ‖ flags ‖ signCount` (4 bytes big-endian).
    ///
    /// - signCount: the KPEX_PASSKEY_* corpus carries no counter attribute
    ///   (KeePassXC's own soft provider emits 0), so callers pass the record's
    ///   counter — 0 for KeePassXC-compatible records.
    public static func assertion(
        rpID: String,
        signCount: UInt32,
        flags: Flags
    ) throws -> Data {
        var data = try rpIdHash(rpID)
        data.append(flags.byte)
        data.append(contentsOf: bigEndianBytes(signCount))
        return data
    }

    /// Registration layout: the assertion layout with the ATTESTED flag
    /// (0x40) set, followed by the attested credential data —
    /// `AAGUID (16×0x00) ‖ credIdLen (2B BE) ‖ credentialID ‖ COSE key`.
    public static func registration(
        rpID: String,
        signCount: UInt32,
        flags: Flags,
        credentialID: Data,
        attestedCredentialKey: Data
    ) throws -> Data {
        guard credentialID.count <= 1023 else {
            throw WebAuthnError.credentialIDTooLong
        }
        var data = try rpIdHash(rpID)
        data.append(flags.byte | 0x40) // AT — attested credential data present
        data.append(contentsOf: bigEndianBytes(signCount))
        data.append(Data(repeating: 0x00, count: 16)) // AAGUID (none)
        data.append(contentsOf: bigEndianBytes(UInt16(credentialID.count)))
        data.append(credentialID)
        data.append(attestedCredentialKey)
        return data
    }

    /// Big-endian byte form of a fixed-width integer.
    private static func bigEndianBytes<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }
}

/// The assertion half of D-10's 一进一出: build the ES256 signature over
/// `authenticatorData ‖ clientDataHash` from a STORED `PasskeyCredential`
/// (the KPEX_PASSKEY_* fields the acceptance criteria scope). The private key
/// exists only in memory for the duration of this call — it is never rendered,
/// copied, logged, or exported (T-06-13).
public enum PasskeyAssertion {

    /// The bytes an `ASPasskeyAssertionCredential` carries.
    public struct Output: Sendable, Equatable {
        /// The assertion authenticator data (rpIdHash from the STORED rpID).
        public let authenticatorData: Data
        /// The ECDSA signature in DER/ASN.1 form (WebAuthn ES256 expectation).
        public let signature: Data
    }

    /// Builds the assertion for `credential` against `clientDataHash`.
    ///
    /// - Parameters:
    ///   - isUserVerified: ONLY true when user verification actually happened
    ///     in this request (biometric unlock) — passed through to the flags.
    ///   - signCount: see `AuthenticatorData.assertion` (0 for KPEX records).
    public static func build(
        credential: PasskeyCredential,
        clientDataHash: Data,
        isUserVerified: Bool,
        signCount: UInt32 = 0
    ) throws -> Output {
        guard let key = try? P256.Signing.PrivateKey(
            pemRepresentation: credential.privateKeyPEM) else {
            throw WebAuthnError.privateKeyConversionFailed
        }
        let flags = AuthenticatorData.Flags(
            isUserVerified: isUserVerified,
            backupEligibility: credential.backupEligibility,
            backupState: credential.backupState)
        let authenticatorData = try AuthenticatorData.assertion(
            rpID: credential.rpID,
            signCount: signCount,
            flags: flags)
        let signature = try key.signature(for: authenticatorData + clientDataHash)
        return Output(
            authenticatorData: authenticatorData,
            // CryptoKit's `rawRepresentation` is the P1363 r‖s form; WebAuthn
            // ES256 expects the ASN.1 DER encoding — caught by the
            // independently-verifying vector test.
            signature: signature.derRepresentation)
    }
}

/// The registration half of D-10's 一进一出: generate the credential material
/// for a NEW passkey. The P-256 keypair is generated locally (CryptoKit);
/// credential ID and user handle come from the injected random seam
/// (`SecureRandom.bytes` in production, a deterministic seed in tests).
/// The record persists in KeePassXC-compatible KPEX_PASSKEY_* form via
/// `PasskeyCredential` + `KdbxPasskey.write` semantics on the native path.
public enum PasskeyRegistration {

    /// Everything the caller needs to complete the system request AND
    /// persist the record.
    public struct Material: Sendable, Equatable {
        /// 32 random bytes (base64url-encoded for storage).
        public let credentialID: Data
        /// 32 random bytes (base64url-encoded for storage), or the RP's
        /// requested handle when the request carried one.
        public let userHandle: Data
        /// PKCS#8 PEM of the generated private key — stored verbatim, never
        /// rendered anywhere (T-06-13).
        public let privateKeyPEM: String
        /// The registration authenticator data (UP|UV|AT flags + attested
        /// credential data).
        public let authenticatorData: Data
        /// The attestation object: canonical CBOR `{fmt: "none", attStmt: {},
        /// authData: …}` — self-attestation, no attestation statement.
        public let attestationObject: Data
    }

    /// Builds the registration material for a new passkey at `rpID`.
    ///
    /// - Parameters:
    ///   - isUserVerified: ONLY true when user verification actually happened
    ///     in this request — never assumed (T-06-14).
    ///   - backupEligibility/backupState: fresh credentials are backup-capable
    ///     and start in the backed-up state (multi-device sync); passed
    ///     explicitly so the flag inputs stay honest and overridable.
    ///   - random: the SecureRandom seam — production passes
    ///     `SecureRandom.bytes(count:)`, tests a deterministic seed.
    public static func build(
        rpID: String,
        clientDataHash: Data,
        isUserVerified: Bool,
        backupEligibility: Bool = true,
        backupState: Bool = true,
        random: (Int) -> Data = { SecureRandom.bytes(count: $0) }
    ) throws -> Material {
        let key = P256.Signing.PrivateKey()
        let credentialID = random(32)
        let userHandle = random(32)
        let coseKey = COSEKey.ec2P256(key.publicKey)
        let flags = AuthenticatorData.Flags(
            isUserVerified: isUserVerified,
            backupEligibility: backupEligibility,
            backupState: backupState)
        let authenticatorData = try AuthenticatorData.registration(
            rpID: rpID,
            signCount: 0,
            flags: flags,
            credentialID: credentialID,
            attestedCredentialKey: coseKey)
        let attestationObject = CBOR.encode(.map([
            (.text("fmt"), .text("none")),
            (.text("attStmt"), .map([])),
            (.text("authData"), .byteString(authenticatorData)),
        ]))
        return Material(
            credentialID: credentialID,
            userHandle: userHandle,
            privateKeyPEM: key.pemRepresentation,
            authenticatorData: authenticatorData,
            attestationObject: attestationObject)
    }
}
