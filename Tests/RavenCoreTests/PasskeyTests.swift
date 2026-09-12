import XCTest
@testable import RavenCore

/// CORE-07: passkey storage in KDBX entries, KeePassXC 2.7.x KPEX_PASSKEY
/// layout (D-01/D-02). The fixed synthetic credential below is shared with
/// the committed fixtures kxc-passkey.kdbx / rv-passkey.kdbx
/// (see Tests/Fixtures/Kdbx/MANIFEST.md — all values synthetic).
final class PasskeyTests: XCTestCase {

    // MARK: - Fixed synthetic credential (mirrors the fixture manifest)

    static let fixtureUsername = "alice@example.com"
    static let fixtureRpID = "example.com"
    static let fixtureCredentialID = "-cLXmjDNY0U6pHYpDx7FbENwTKlX95xzV5FQQh0U-38"
    static let fixtureUserHandle = "ngHFbgaTCoa06Mo5sdcLr5cIR_jDSx8WoDsSe7eI9f8"
    static let fixturePEM = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM2NYELpT/P9sW3kV
    qFIMtWUvVIyWyTXMVBj/96uxyYuhRANCAARmIvPFfIOMtnSQmsDXpRcD6ifYB3X6
    ZfRM1QkysuHcAwQ5je4rtYTI7S4vH092dm+MfMCg+c50/LFQLUAXYzGv
    -----END PRIVATE KEY-----
    """

    /// BE="1", BS="0" in the fixtures — the two flags intentionally differ so
    /// reading is proven to distinguish them.
    static func fixtureCredential() -> PasskeyCredential {
        PasskeyCredential(
            username: fixtureUsername,
            rpID: fixtureRpID,
            credentialID: fixtureCredentialID,
            userHandle: fixtureUserHandle,
            privateKeyPEM: fixturePEM,
            backupEligibility: true,
            backupState: false
        )
    }

    private func makeEntry() -> KdbxEntry {
        var entry = KdbxEntry()
        try? KdbxPasskey.write(Self.fixtureCredential(), into: &entry, title: "RavenTest (Passkey)", originURL: "https://example.com/login")
        return entry
    }

    // MARK: - Tracer: full write → file → read round trip

    func testWriteRoundTripThroughKdbxFile() throws {
        let original = Self.fixtureCredential()

        var entry = KdbxEntry()
        try KdbxPasskey.write(original, into: &entry, title: "RavenTest (Passkey)", originURL: "https://example.com/login")

        var doc = KdbxDocument()
        doc.root.entries.append(entry)
        let data = try KdbxWriter.write(doc, credentials: KdbxReader.Credentials(password: "correct-horse-battery"))
        let reopened = try KdbxReader.read(data, credentials: KdbxReader.Credentials(password: "correct-horse-battery"))

        let stored = try XCTUnwrap(reopened.root.entries.first)
        XCTAssertTrue(KdbxPasskey.isPasskey(stored))
        let credential = try XCTUnwrap(try KdbxPasskey.read(from: stored))
        XCTAssertEqual(credential, original, "round trip must preserve the credential verbatim")
    }

    func testWrittenLayoutMatchesKeePassXCConventions() throws {
        let entry = makeEntry()

        // All seven canonical attribute keys present.
        let expectedKeys = [
            KdbxPasskey.usernameKey,
            KdbxPasskey.credentialIDKey,
            KdbxPasskey.privateKeyPEMKey,
            KdbxPasskey.relyingPartyKey,
            KdbxPasskey.userHandleKey,
            KdbxPasskey.backupEligibilityKey,
            KdbxPasskey.backupStateKey,
        ]
        for key in expectedKeys {
            XCTAssertNotNil(entry.value(key), "missing attribute \(key)")
        }

        // Protection layout: secrets protected, metadata not (T-01-01).
        func isProtected(_ key: String) -> Bool {
            entry.strings.first { $0.key == key }?.protected ?? false
        }
        XCTAssertTrue(isProtected(KdbxPasskey.credentialIDKey), "CREDENTIAL_ID must be protected")
        XCTAssertTrue(isProtected(KdbxPasskey.privateKeyPEMKey), "PRIVATE_KEY_PEM must be protected")
        XCTAssertTrue(isProtected(KdbxPasskey.userHandleKey), "USER_HANDLE must be protected")
        XCTAssertFalse(isProtected(KdbxPasskey.usernameKey))
        XCTAssertFalse(isProtected(KdbxPasskey.relyingPartyKey))
        XCTAssertFalse(isProtected(KdbxPasskey.backupEligibilityKey))
        XCTAssertFalse(isProtected(KdbxPasskey.backupStateKey))

        // KeePassXC entry shell.
        XCTAssertEqual(entry.value("Title"), "RavenTest (Passkey)")
        XCTAssertEqual(entry.value("UserName"), "alice@example.com")
        XCTAssertEqual(entry.value("URL"), "https://example.com/login")
        XCTAssertEqual(entry.iconId, 13)
        XCTAssertEqual(entry.tags?.contains("Passkey"), true)
        XCTAssertEqual(entry.value(KdbxPasskey.backupEligibilityKey), "1")
        XCTAssertEqual(entry.value(KdbxPasskey.backupStateKey), "0")
    }

    func testAbsentBackupFlagsDefaultTrue() throws {
        // Hand-built entry with the five required attributes but no BE/BS.
        var entry = KdbxEntry()
        entry.setValue(KdbxPasskey.usernameKey, "alice@example.com")
        entry.setValue(KdbxPasskey.credentialIDKey, "cred", protected: true)
        entry.setValue(KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, protected: true)
        entry.setValue(KdbxPasskey.relyingPartyKey, "example.com")
        entry.setValue(KdbxPasskey.userHandleKey, "handle", protected: true)

        let credential = try XCTUnwrap(try KdbxPasskey.read(from: entry))
        XCTAssertTrue(credential.backupEligibility, "absent FLAG_BE must default true")
        XCTAssertTrue(credential.backupState, "absent FLAG_BS must default true")
    }

    func testNotAPasskeyEntryReturnsNil() throws {
        var entry = KdbxEntry()
        entry.setValue("Title", "Plain record")
        entry.setValue("UserName", "someone")
        XCTAssertNil(try KdbxPasskey.read(from: entry))
    }

    // MARK: - base64url (RFC 4648 §5, unpadded)

    func testBase64URLEncode() {
        XCTAssertEqual(KdbxPasskey.base64URLEncode(Data("hello".utf8)), "aGVsbG8", "no padding")
        XCTAssertEqual(KdbxPasskey.base64URLEncode(Data([0xFB, 0xEF, 0xBE])), "----", "+ mapped to -")
        XCTAssertEqual(KdbxPasskey.base64URLEncode(Data([0xFF, 0xFF])), "__8", "/ mapped to _")
        XCTAssertEqual(KdbxPasskey.base64URLEncode(Data()), "")
    }

    // MARK: - Reader tolerance: legacy keys

    /// Builds a fully valid passkey entry from explicit key/value pairs so
    /// tolerance tests can swap canonical keys for legacy spellings.
    private func entryWithAttributes(_ attributes: [(String, String, Bool)]) -> KdbxEntry {
        var entry = KdbxEntry()
        for (key, value, protected) in attributes {
            entry.setValue(key, value, protected: protected)
        }
        return entry
    }

    func testLegacyCredentialIDKeyIsAccepted() throws {
        let entry = entryWithAttributes([
            (KdbxPasskey.usernameKey, Self.fixtureUsername, false),
            (KdbxPasskey.legacyGeneratedUserIDKey, "legacy-cred-id", true), // no canonical CREDENTIAL_ID
            (KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, true),
            (KdbxPasskey.relyingPartyKey, Self.fixtureRpID, false),
            (KdbxPasskey.userHandleKey, Self.fixtureUserHandle, true),
            (KdbxPasskey.backupEligibilityKey, "1", false),
            (KdbxPasskey.backupStateKey, "1", false),
        ])
        let credential = try XCTUnwrap(try KdbxPasskey.read(from: entry))
        XCTAssertEqual(credential.credentialID, "legacy-cred-id", "GENERATED_USER_ID fallback")
    }

    func testLegacyUsernameKeyIsAccepted() throws {
        let entry = entryWithAttributes([
            (KdbxPasskey.legacyUsernameKey, "legacy-user", false), // no canonical USERNAME
            (KdbxPasskey.credentialIDKey, Self.fixtureCredentialID, true),
            (KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, true),
            (KdbxPasskey.relyingPartyKey, Self.fixtureRpID, false),
            (KdbxPasskey.userHandleKey, Self.fixtureUserHandle, true),
        ])
        let credential = try XCTUnwrap(try KdbxPasskey.read(from: entry))
        XCTAssertEqual(credential.username, "legacy-user", "KPXC_PASSKEY_USERNAME fallback")
    }

    func testCanonicalKeysWinOverLegacyWhenBothPresent() throws {
        let entry = entryWithAttributes([
            (KdbxPasskey.usernameKey, Self.fixtureUsername, false),
            (KdbxPasskey.legacyUsernameKey, "legacy-user", false),
            (KdbxPasskey.credentialIDKey, Self.fixtureCredentialID, true),
            (KdbxPasskey.legacyGeneratedUserIDKey, "legacy-cred-id", true),
            (KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, true),
            (KdbxPasskey.relyingPartyKey, Self.fixtureRpID, false),
            (KdbxPasskey.userHandleKey, Self.fixtureUserHandle, true),
        ])
        let credential = try XCTUnwrap(try KdbxPasskey.read(from: entry))
        XCTAssertEqual(credential.username, Self.fixtureUsername, "canonical username preferred")
        XCTAssertEqual(credential.credentialID, Self.fixtureCredentialID, "canonical credential ID preferred")
    }

    // MARK: - Reader tolerance: BE/BS value matrix

    func testBackupFlagValueMatrix() throws {
        func credentialWithFlag(_ key: String, _ value: String) throws -> PasskeyCredential {
            let entry = entryWithAttributes([
                (KdbxPasskey.usernameKey, Self.fixtureUsername, false),
                (KdbxPasskey.credentialIDKey, Self.fixtureCredentialID, true),
                (KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, true),
                (KdbxPasskey.relyingPartyKey, Self.fixtureRpID, false),
                (KdbxPasskey.userHandleKey, Self.fixtureUserHandle, true),
                (key, value, false),
            ])
            return try XCTUnwrap(try KdbxPasskey.read(from: entry))
        }

        // true: "1" or case-insensitive "true"
        for value in ["1", "true", "TRUE", "True"] {
            let be = try credentialWithFlag(KdbxPasskey.backupEligibilityKey, value)
            XCTAssertTrue(be.backupEligibility, "FLAG_BE=\(value) must read true")
        }
        // false: anything else (including empty string)
        for value in ["0", "yes", ""] {
            let be = try credentialWithFlag(KdbxPasskey.backupEligibilityKey, value)
            XCTAssertFalse(be.backupEligibility, "FLAG_BE=\(value) must read false")
        }
        // Same matrix applies to FLAG_BS.
        let bsTrue = try credentialWithFlag(KdbxPasskey.backupStateKey, "true")
        XCTAssertTrue(bsTrue.backupState)
        let bsFalse = try credentialWithFlag(KdbxPasskey.backupStateKey, "0")
        XCTAssertFalse(bsFalse.backupState)
    }

    // MARK: - Negative cases (exact typed errors; T-01-02: no values in errors)

    func testMissingUserHandleThrowsExactCase() throws {
        let entry = entryWithAttributes([
            (KdbxPasskey.usernameKey, Self.fixtureUsername, false),
            (KdbxPasskey.credentialIDKey, Self.fixtureCredentialID, true),
            (KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, true),
            (KdbxPasskey.relyingPartyKey, Self.fixtureRpID, false),
            // no USER_HANDLE
        ])
        XCTAssertThrowsError(try KdbxPasskey.read(from: entry)) { error in
            XCTAssertEqual(
                error as? KdbxPasskeyError,
                .missingRequiredAttribute("KPEX_PASSKEY_USER_HANDLE")
            )
        }
    }

    func testEmptyCredentialIDThrowsExactCase() throws {
        let entry = entryWithAttributes([
            (KdbxPasskey.usernameKey, Self.fixtureUsername, false),
            (KdbxPasskey.credentialIDKey, "", true),
            (KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, true),
            (KdbxPasskey.relyingPartyKey, Self.fixtureRpID, false),
            (KdbxPasskey.userHandleKey, Self.fixtureUserHandle, true),
        ])
        XCTAssertThrowsError(try KdbxPasskey.read(from: entry)) { error in
            XCTAssertEqual(error as? KdbxPasskeyError, .emptyCredentialId)
        }
    }

    func testInvalidRelyingPartyThrowsExactCase() throws {
        for badRpID in ["https://example.com", "example.com/path"] {
            let entry = entryWithAttributes([
                (KdbxPasskey.usernameKey, Self.fixtureUsername, false),
                (KdbxPasskey.credentialIDKey, Self.fixtureCredentialID, true),
                (KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, true),
                (KdbxPasskey.relyingPartyKey, badRpID, false),
                (KdbxPasskey.userHandleKey, Self.fixtureUserHandle, true),
            ])
            XCTAssertThrowsError(try KdbxPasskey.read(from: entry), "rpID \(badRpID)") { error in
                XCTAssertEqual(error as? KdbxPasskeyError, .invalidRelyingParty)
            }
        }
    }

    func testPEMWithoutEndMarkerThrowsExactCase() throws {
        let beginOnly = Self.fixturePEM.replacingOccurrences(
            of: "-----END PRIVATE KEY-----", with: "")
        let entry = entryWithAttributes([
            (KdbxPasskey.usernameKey, Self.fixtureUsername, false),
            (KdbxPasskey.credentialIDKey, Self.fixtureCredentialID, true),
            (KdbxPasskey.privateKeyPEMKey, beginOnly, true),
            (KdbxPasskey.relyingPartyKey, Self.fixtureRpID, false),
            (KdbxPasskey.userHandleKey, Self.fixtureUserHandle, true),
        ])
        XCTAssertThrowsError(try KdbxPasskey.read(from: entry)) { error in
            XCTAssertEqual(error as? KdbxPasskeyError, .malformedPrivateKeyPEM)
        }
    }

    // MARK: - Write validation atomicity

    func testWriteRejectsInvalidCredentialWithoutTouchingEntry() throws {
        var entry = makeEntry()
        let snapshot = entry.strings // KdbxString is Equatable — full content snapshot

        let invalid: [PasskeyCredential] = [
            PasskeyCredential(username: Self.fixtureUsername, rpID: Self.fixtureRpID, credentialID: "", userHandle: Self.fixtureUserHandle, privateKeyPEM: Self.fixturePEM, backupEligibility: true, backupState: true),
            PasskeyCredential(username: Self.fixtureUsername, rpID: "https://example.com", credentialID: Self.fixtureCredentialID, userHandle: Self.fixtureUserHandle, privateKeyPEM: Self.fixturePEM, backupEligibility: true, backupState: true),
            PasskeyCredential(username: Self.fixtureUsername, rpID: Self.fixtureRpID, credentialID: Self.fixtureCredentialID, userHandle: "", privateKeyPEM: Self.fixturePEM, backupEligibility: true, backupState: true),
            PasskeyCredential(username: Self.fixtureUsername, rpID: Self.fixtureRpID, credentialID: Self.fixtureCredentialID, userHandle: Self.fixtureUserHandle, privateKeyPEM: "not a pem", backupEligibility: true, backupState: true),
        ]
        for credential in invalid {
            XCTAssertThrowsError(try KdbxPasskey.write(credential, into: &entry, title: "t", originURL: nil))
        }
        XCTAssertEqual(entry.strings, snapshot, "failed writes must leave entry.strings untouched")
    }

    // MARK: - Write: stale legacy key cleanup (W-01)

    func testWriteOnLegacyAuthoredEntryRemovesStaleLegacyKeys() throws {
        // An entry authored by KeePassXC ≤ 2.7.9 / StrongBox carries the
        // legacy spellings alongside the canonical keys.
        var entry = entryWithAttributes([
            (KdbxPasskey.usernameKey, Self.fixtureUsername, false),
            (KdbxPasskey.legacyUsernameKey, "stale-user", false),
            (KdbxPasskey.credentialIDKey, Self.fixtureCredentialID, true),
            (KdbxPasskey.legacyGeneratedUserIDKey, "stale-cred-id", true),
            (KdbxPasskey.privateKeyPEMKey, Self.fixturePEM, true),
            (KdbxPasskey.relyingPartyKey, Self.fixtureRpID, false),
            (KdbxPasskey.userHandleKey, Self.fixtureUserHandle, true),
        ])

        // Rotate the credential. KeePassXC's read path prefers
        // GENERATED_USER_ID whenever present, so the stale legacy copy must
        // not survive the update.
        var updated = Self.fixtureCredential()
        updated.username = "rotated@example.com"
        updated.credentialID = "ROTATED-CREDENTIAL-ID"
        try KdbxPasskey.write(updated, into: &entry, title: "Rotated", originURL: nil)

        XCTAssertFalse(
            entry.strings.contains { $0.key == KdbxPasskey.legacyGeneratedUserIDKey },
            "stale GENERATED_USER_ID must be removed on write"
        )
        XCTAssertFalse(
            entry.strings.contains { $0.key == KdbxPasskey.legacyUsernameKey },
            "stale KPXC_PASSKEY_USERNAME must be removed on write"
        )
        XCTAssertEqual(entry.value(KdbxPasskey.credentialIDKey), "ROTATED-CREDENTIAL-ID")

        // RavenVault's canonical-first read and KeePassXC's legacy-first read
        // now see the same credential.
        let reread = try XCTUnwrap(try KdbxPasskey.read(from: entry))
        XCTAssertEqual(reread, updated)
    }

    // MARK: - Write: shell rewrite (I-02)

    func testWriteWithNilOriginURLRemovesStaleURL() throws {
        // The write shell is rewritten wholesale: a nil originURL must clear a
        // URL left by a previous write, not preserve a stale origin.
        var entry = makeEntry() // carries URL https://example.com/login
        XCTAssertNotNil(entry.value("URL"))

        try KdbxPasskey.write(Self.fixtureCredential(), into: &entry, title: "Rotated", originURL: nil)

        XCTAssertNil(entry.value("URL"), "nil originURL must remove the stale URL attribute")
        XCTAssertEqual(entry.value("Title"), "Rotated")
    }

    func testWriteReplacesOriginURLWhenProvided() throws {
        var entry = makeEntry()
        try KdbxPasskey.write(Self.fixtureCredential(), into: &entry, title: "Moved", originURL: "https://example.net/auth")

        XCTAssertEqual(entry.value("URL"), "https://example.net/auth")
    }

    // MARK: - isPasskey boundaries

    func testIsPasskeyBoundaries() {
        XCTAssertFalse(KdbxPasskey.isPasskey(KdbxEntry()), "no attributes → not a passkey")

        var flagOnly = KdbxEntry()
        flagOnly.setValue(KdbxPasskey.backupEligibilityKey, "1")
        XCTAssertTrue(KdbxPasskey.isPasskey(flagOnly), "a single KPEX_PASSKEY* attribute is enough")
    }
}
