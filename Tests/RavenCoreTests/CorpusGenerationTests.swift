import XCTest
@testable import RavenCore

/// Opt-in generation of the rv-* corpus files (RavenCore-written, verified
/// externally by keepassxc-cli inside scripts/generate-corpus.sh).
///   GENERATE_CORPUS=1 swift test --filter CorpusGenerationTests
final class CorpusGenerationTests: XCTestCase {

    func testGenerateRavenCoreVariantFixtures() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_CORPUS"] == "1" else {
            throw XCTSkip("Set GENERATE_CORPUS=1 to (re)generate rv-* corpus fixtures")
        }

        let dir = URL(fileURLWithPath: TestFixtures.packageRoot)
            .appendingPathComponent("Packages/RavenCore/Tests/Fixtures/Kdbx")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let credentials = try KdbxReader.Credentials(password: "correct-horse-battery")

        func document() -> KdbxDocument {
            var doc = KdbxDocument()
            doc.meta.generator = "RavenVault"
            var entry = KdbxEntry()
            entry.setValue("Title", "RavenVaultEntry")
            entry.setValue("UserName", "rv-user")
            entry.setValue("Password", "pw-rv-secret", protected: true)
            doc.root.entries.append(entry)
            return doc
        }

        func argonVariant(uuid: UUID) -> KdbxWriter.Options {
            var kdf = VariantDictionary()
            kdf["$UUID"] = .byteArray(uuid.data)
            kdf["V"] = .uint32(0x13)
            kdf["I"] = .uint32(2)
            kdf["M"] = .uint64(65_536 * 1024) // bytes
            kdf["P"] = .uint32(2)
            var options = KdbxWriter.Options()
            options.kdfParameters = kdf
            return options
        }

        var variants: [(String, KdbxWriter.Options)] = []
        variants.append(("rv-argon2d.kdbx", argonVariant(uuid: KdbxCrypto.argon2dUUID)))
        variants.append(("rv-aeskdf.kdbx", KdbxWriter.Options.aesKdf(rounds: 600_000)))
        var chacha = KdbxWriter.Options.argon2idDefaults()
        chacha.cipherId = KdbxCrypto.chacha20CipherUUID
        variants.append(("rv-chacha20.kdbx", chacha))
        var nocompress = KdbxWriter.Options.argon2idDefaults()
        nocompress.compression = .none
        variants.append(("rv-nocompress.kdbx", nocompress))

        for (name, options) in variants {
            let data = try KdbxWriter.write(document(), credentials: credentials, options: options)
            try data.write(to: dir.appendingPathComponent(name))
            // Self-check: our own reader must accept it.
            _ = try KdbxReader.read(data, credentials: credentials)
        }
    }

    // MARK: - Passkey fixtures (02-01-03, CORE-07/D-03)

    /// The synthetic passkey document shared by rv-passkey.kdbx and the
    /// kxc-passkey.kdbx authoring seed. Values come from the single fixture
    /// definition in PasskeyTests (mirrored in Tests/Fixtures/Kdbx/MANIFEST.md):
    /// rpName "RavenTest", rpID "example.com", FLAG_BE="1", FLAG_BS="0".
    func passkeyDocument() -> KdbxDocument {
        var doc = KdbxDocument()
        doc.meta.generator = "RavenVault"
        var entry = KdbxEntry()
        try? KdbxPasskey.write(
            PasskeyTests.fixtureCredential(),
            into: &entry,
            title: "RavenTest (Passkey)",
            originURL: "https://example.com/login"
        )
        doc.root.entries.append(entry)
        return doc
    }

    /// rv-passkey.kdbx (us → external oracle): written by RavenCore's
    /// KdbxPasskey.write, then verified attribute-by-attribute with
    /// keepassxc-cli inside scripts/generate-corpus.sh.
    func testGenerateRavenCorePasskeyFixture() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_CORPUS"] == "1" else {
            throw XCTSkip("Set GENERATE_CORPUS=1 to (re)generate rv-passkey.kdbx")
        }

        let dir = URL(fileURLWithPath: TestFixtures.packageRoot)
            .appendingPathComponent("Packages/RavenCore/Tests/Fixtures/Kdbx")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let credentials = try KdbxReader.Credentials(password: "correct-horse-battery")

        let data = try KdbxWriter.write(passkeyDocument(), credentials: credentials)
        try data.write(to: dir.appendingPathComponent("rv-passkey.kdbx"))
        // Self-check: our own reader must accept it and return the credential.
        let doc = try KdbxReader.read(data, credentials: credentials)
        let entry = try XCTUnwrap(doc.root.allEntries().first { $0.name == "RavenTest (Passkey)" })
        let credential = try XCTUnwrap(try KdbxPasskey.read(from: entry))
        XCTAssertEqual(credential, PasskeyTests.fixtureCredential())
    }

    /// kxc-passkey.kdbx authoring seed. KeePassXC's CLI cannot create
    /// protected custom attributes and this machine has no operable GUI for
    /// one-time fixture authoring, so the committed fixture is produced by
    /// having KeePassXC 2.7.12 itself re-save (db-edit) a database whose
    /// entry was authored with KdbxPasskey.write — the committed file's bytes
    /// are produced by KeePassXC's own writer (provenance recorded in
    /// scripts/CROSS-VALIDATION.md). One-time, dev-machine only:
    ///   GENERATE_KXC_PASSKEY=1 KXC_PASSKEY_OUT=/tmp/kxc-passkey-seed.kdbx \
    ///     swift test --filter testGenerateKeePassXCPasskeyAuthoringSeed
    func testGenerateKeePassXCPasskeyAuthoringSeed() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_KXC_PASSKEY"] == "1" else {
            throw XCTSkip("Set GENERATE_KXC_PASSKEY=1 (+ KXC_PASSKEY_OUT) to write the kxc-passkey authoring seed")
        }
        let out = try XCTUnwrap(
            ProcessInfo.processInfo.environment["KXC_PASSKEY_OUT"],
            "KXC_PASSKEY_OUT must point at the seed output path (outside Tests/Fixtures)"
        )
        let data = try KdbxWriter.write(
            passkeyDocument(),
            credentials: KdbxReader.Credentials(password: "correct-horse-battery")
        )
        try data.write(to: URL(fileURLWithPath: out))
    }
}
