import Foundation

/// Passkey (FIDO2/WebAuthn credential) storage inside KDBX entries (CORE-07).
///
/// A passkey is nothing but an ordinary entry carrying seven custom string
/// attributes in the KeePassXC 2.7.x `KPEX_PASSKEY_*` layout (D-01); there is
/// no XML schema change and no CustomData involvement. This helper is a thin,
/// transparent codec over `KdbxEntry.strings` — `KdbxDocument` is untouched
/// (D-02). The write layout mirrors KeePassXC's
/// `BrowserService.cpp addPasskeyToEntry` (research pin: 2.7.x lineage,
/// KeePassXC PR #10420 legacy-key compat, PR #13042 backup-flag defaults):
///
/// - `KPEX_PASSKEY_CREDENTIAL_ID`, `KPEX_PASSKEY_PRIVATE_KEY_PEM` and
///   `KPEX_PASSKEY_USER_HANDLE` are always written with `Protected="True"`,
///   exactly like a KeePassXC-created passkey entry.
/// - Entry shell on write = KeePassXC's fresh-passkey conventions:
///   `Title`, `UserName`, optional `URL`, icon `13`, tag `"Passkey"`.
/// - Backup flags: attribute absent ⇒ `true` (KeePassXC `DEFAULT_BE_FLAG` /
///   `DEFAULT_BS_FLAG` are true — absent never means false); present ⇒ true
///   iff the value is `"1"` or a case-insensitive `"true"`.
/// - Read tolerance: legacy keys `KPEX_PASSKEY_GENERATED_USER_ID` (StrongBox
///   compat) and `KPXC_PASSKEY_USERNAME` (2.7.7-era name kept for StrongBox)
///   are accepted when the canonical keys are absent; writes emit canonical
///   keys only and remove stale legacy copies — KeePassXC's own read path
///   prefers `GENERATED_USER_ID` whenever present, so a stale copy left on an
///   updated entry would keep browser integration matching the OLD credential
///   ID while this module reads the new one.
/// - PEM is validated by marker presence only (PKCS#8 BEGIN/END) — RSA and
///   Ed25519 passkeys exist, so the key type is never assumed.
/// - Error payloads carry attribute key names only, never attribute values
///   (no credential material in error text).

/// Errors thrown by `KdbxPasskey`. `Equatable` for exact-case test
/// assertions, mirroring the engine's per-module error enum convention.
/// Payloads are attribute **key names** only — never attribute values.
public enum KdbxPasskeyError: Error, Equatable {
    /// A required `KPEX_PASSKEY_*` attribute is missing (payload = canonical key name).
    case missingRequiredAttribute(String)
    /// Credential ID or user handle is present but empty.
    case emptyCredentialId
    /// Relying party is empty, contains "://", or contains "/".
    case invalidRelyingParty
    /// Private key PEM lacks the PKCS#8 BEGIN or END marker.
    case malformedPrivateKeyPEM
}

/// The WebAuthn credential material carried by a passkey entry. All strings
/// are stored and compared verbatim — the engine never re-encodes
/// interoperability payloads (KeePassXC does not re-validate them at rest).
public struct PasskeyCredential: Sendable, Equatable {
    /// `KPEX_PASSKEY_USERNAME` (plain string).
    public var username: String
    /// `KPEX_PASSKEY_RELYING_PARTY` — RP ID (registrable domain, no scheme/path).
    public var rpID: String
    /// `KPEX_PASSKEY_CREDENTIAL_ID` — base64url string, stored verbatim.
    public var credentialID: String
    /// `KPEX_PASSKEY_USER_HANDLE` — base64url string, stored verbatim.
    public var userHandle: String
    /// `KPEX_PASSKEY_PRIVATE_KEY_PEM` — PKCS#8 PEM, stored verbatim.
    public var privateKeyPEM: String
    /// `KPEX_PASSKEY_FLAG_BE` — backup eligibility (absent ⇒ true).
    public var backupEligibility: Bool
    /// `KPEX_PASSKEY_FLAG_BS` — backup state (absent ⇒ true).
    public var backupState: Bool

    /// Creates a credential; all strings are stored verbatim.
    public init(
        username: String,
        rpID: String,
        credentialID: String,
        userHandle: String,
        privateKeyPEM: String,
        backupEligibility: Bool,
        backupState: Bool
    ) {
        self.username = username
        self.rpID = rpID
        self.credentialID = credentialID
        self.userHandle = userHandle
        self.privateKeyPEM = privateKeyPEM
        self.backupEligibility = backupEligibility
        self.backupState = backupState
    }
}

/// Namespace for the passkey codec: detection, read, write, and encoding
/// helpers over ordinary `KdbxEntry` string attributes (D-01/D-02).
public enum KdbxPasskey {

    // MARK: - Attribute keys (canonical KeePassXC 2.7.x layout)

    /// Username attribute (plain string).
    public static let usernameKey = "KPEX_PASSKEY_USERNAME"
    /// Credential ID attribute (base64url, protected on write).
    public static let credentialIDKey = "KPEX_PASSKEY_CREDENTIAL_ID"
    /// Private key PEM attribute (PKCS#8, protected on write).
    public static let privateKeyPEMKey = "KPEX_PASSKEY_PRIVATE_KEY_PEM"
    /// Relying-party ID attribute (registrable domain).
    public static let relyingPartyKey = "KPEX_PASSKEY_RELYING_PARTY"
    /// User handle attribute (base64url, protected on write).
    public static let userHandleKey = "KPEX_PASSKEY_USER_HANDLE"
    /// Backup-eligibility flag attribute ("1"/"0").
    public static let backupEligibilityKey = "KPEX_PASSKEY_FLAG_BE"
    /// Backup-state flag attribute ("1"/"0").
    public static let backupStateKey = "KPEX_PASSKEY_FLAG_BS"

    /// Legacy spellings tolerated on read only (StrongBox compat); never written.
    public static let legacyGeneratedUserIDKey = "KPEX_PASSKEY_GENERATED_USER_ID"
    /// Legacy spelling of the username key (2.7.7-era), tolerated on read.
    public static let legacyUsernameKey = "KPXC_PASSKEY_USERNAME"

    /// Any attribute key with this prefix marks the entry as a passkey.
    private static let keyPrefix = "KPEX_PASSKEY"

    private static let pemBeginMarker = "-----BEGIN PRIVATE KEY-----"
    private static let pemEndMarker = "-----END PRIVATE KEY-----"

    // MARK: - Detection

    /// True when the entry carries any attribute whose key starts with
    /// `KPEX_PASSKEY` (KeePassXC `hasPasskey` semantics).
    ///
    /// Deliberate asymmetry with `read` (02-REVIEW.md I-03): an entry carrying
    /// only a legacy-spelling attribute can never trip this prefix check, so
    /// `read` returns `nil` (not a typed error) for it. That matches
    /// KeePassXC's own detection semantics — any real passkey entry also has
    /// prefixed keys — so this is by design, not an oversight.
    public static func isPasskey(_ entry: KdbxEntry) -> Bool {
        entry.strings.contains { $0.key.hasPrefix(keyPrefix) }
    }

    // MARK: - Read

    /// Reads the passkey credential from an entry.
    /// Returns `nil` when the entry has no `KPEX_PASSKEY*` attribute (not a
    /// passkey); throws a typed error on a malformed passkey entry.
    public static func read(from entry: KdbxEntry) throws -> PasskeyCredential? {
        guard isPasskey(entry) else { return nil }

        guard let username = lookup(entry, canonical: usernameKey, legacy: legacyUsernameKey) else {
            throw KdbxPasskeyError.missingRequiredAttribute(usernameKey)
        }
        guard let credentialID = lookup(entry, canonical: credentialIDKey, legacy: legacyGeneratedUserIDKey) else {
            throw KdbxPasskeyError.missingRequiredAttribute(credentialIDKey)
        }
        guard let privateKeyPEM = entry.value(privateKeyPEMKey) else {
            throw KdbxPasskeyError.missingRequiredAttribute(privateKeyPEMKey)
        }
        guard let rpID = entry.value(relyingPartyKey) else {
            throw KdbxPasskeyError.missingRequiredAttribute(relyingPartyKey)
        }
        guard let userHandle = entry.value(userHandleKey) else {
            throw KdbxPasskeyError.missingRequiredAttribute(userHandleKey)
        }

        try validate(
            username: username,
            credentialID: credentialID,
            userHandle: userHandle,
            rpID: rpID,
            privateKeyPEM: privateKeyPEM
        )

        return PasskeyCredential(
            username: username,
            rpID: rpID,
            credentialID: credentialID,
            userHandle: userHandle,
            privateKeyPEM: privateKeyPEM,
            backupEligibility: parseFlag(entry, backupEligibilityKey),
            backupState: parseFlag(entry, backupStateKey)
        )
    }

    // MARK: - Write

    /// Writes the full KeePassXC passkey attribute set into `entry` with the
    /// KeePassXC protection layout, plus the fresh-passkey entry shell
    /// (Title/UserName/URL/icon 13/"Passkey" tag). Validation happens before
    /// any mutation: an invalid credential leaves `entry` untouched. Updating
    /// an entry authored by KeePassXC ≤ 2.7.9 or StrongBox also removes any
    /// stale legacy spellings (`KPEX_PASSKEY_GENERATED_USER_ID`,
    /// `KPXC_PASSKEY_USERNAME`) so the canonical set stays the single source
    /// of truth. The full shell is rewritten: `originURL: nil` removes any
    /// pre-existing `URL` attribute rather than leaving a stale one behind
    /// (02-REVIEW.md I-02).
    public static func write(
        _ credential: PasskeyCredential,
        into entry: inout KdbxEntry,
        title: String,
        originURL: String?
    ) throws {
        try validate(
            username: credential.username,
            credentialID: credential.credentialID,
            userHandle: credential.userHandle,
            rpID: credential.rpID,
            privateKeyPEM: credential.privateKeyPEM
        )

        setString(&entry, key: usernameKey, value: credential.username, protected: false)
        setString(&entry, key: credentialIDKey, value: credential.credentialID, protected: true)
        setString(&entry, key: privateKeyPEMKey, value: credential.privateKeyPEM, protected: true)
        setString(&entry, key: relyingPartyKey, value: credential.rpID, protected: false)
        setString(&entry, key: userHandleKey, value: credential.userHandle, protected: true)
        setString(&entry, key: backupEligibilityKey, value: credential.backupEligibility ? "1" : "0", protected: false)
        setString(&entry, key: backupStateKey, value: credential.backupState ? "1" : "0", protected: false)

        // Drop stale legacy spellings when updating an entry authored by
        // KeePassXC ≤ 2.7.9 / StrongBox: KeePassXC's read path prefers
        // `GENERATED_USER_ID` whenever present, so a stale copy would keep
        // browser integration matching the old credential ID after the
        // update. Canonical keys only (see type-level note).
        entry.strings.removeAll {
            $0.key == legacyGeneratedUserIDKey || $0.key == legacyUsernameKey
        }

        // KeePassXC new-passkey entry shell (rpName lives only in the title).
        // The shell is rewritten wholesale (I-02): a nil originURL clears any
        // pre-existing URL attribute instead of leaving a stale one behind.
        setString(&entry, key: "Title", value: title, protected: false)
        setString(&entry, key: "UserName", value: credential.username, protected: false)
        if let originURL {
            setString(&entry, key: "URL", value: originURL, protected: false)
        } else {
            entry.strings.removeAll { $0.key == "URL" }
        }
        entry.iconId = 13
        entry.tags = "Passkey"
    }

    // MARK: - Encoding convenience

    /// RFC 4648 §5 base64url, unpadded — the encoding KeePassXC uses for
    /// credential IDs and user handles (ID_BYTES = 32 random bytes typical).
    public static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: - Private

    /// Canonical key preferred when both spellings are present (planner
    /// decision for 02-01; KeePassXC itself prefers the legacy credential-ID
    /// key, but canonical-first keeps writes and reads aligned).
    private static func lookup(_ entry: KdbxEntry, canonical: String, legacy: String) -> String? {
        if let canonicalValue = entry.value(canonical) { return canonicalValue }
        return entry.value(legacy)
    }

    /// Absent ⇒ true (KeePassXC DEFAULT_BE_FLAG / DEFAULT_BS_FLAG);
    /// present ⇒ true iff `"1"` or case-insensitive `"true"`.
    private static func parseFlag(_ entry: KdbxEntry, _ key: String) -> Bool {
        guard let raw = entry.value(key) else { return true }
        return raw == "1" || raw.lowercased() == "true"
    }

    /// Shared validation for read and write (identical rules on both sides).
    /// Throws before any mutation when used on the write path.
    private static func validate(
        username: String,
        credentialID: String,
        userHandle: String,
        rpID: String,
        privateKeyPEM: String
    ) throws {
        _ = username // tolerated empty: KeePassXC accepts a username-less passkey entry
        if credentialID.isEmpty || userHandle.isEmpty {
            throw KdbxPasskeyError.emptyCredentialId
        }
        if rpID.isEmpty || rpID.contains("://") || rpID.contains("/") {
            throw KdbxPasskeyError.invalidRelyingParty
        }
        if !privateKeyPEM.contains(pemBeginMarker) || !privateKeyPEM.contains(pemEndMarker) {
            throw KdbxPasskeyError.malformedPrivateKeyPEM
        }
    }

    /// Sets a string, replacing any existing value *and* protection flag
    /// (the entry's own `setValue` merge keeps a pre-existing `protected`
    /// flag, which would break the fixed KeePassXC protection layout).
    private static func setString(_ entry: inout KdbxEntry, key: String, value: String, protected: Bool) {
        if let idx = entry.strings.firstIndex(where: { $0.key == key }) {
            entry.strings[idx] = KdbxString(key: key, value: value, protected: protected)
        } else {
            entry.strings.append(KdbxString(key: key, value: value, protected: protected))
        }
    }
}
