import XCTest
@testable import RavenCore

/// CORE-04 interop gate (D-11): every committed corpus fixture must be read
/// correctly, survive a semantic write→read round trip, and reject wrong
/// credentials. The gate NEVER silently passes on an empty directory.
/// Expected values mirror Tests/Fixtures/Kdbx/MANIFEST.md.
final class CorpusGateTests: XCTestCase {

    static let fixturesDirectory: URL = URL(fileURLWithPath: TestFixtures.packageRoot)
        .appendingPathComponent("Tests/Fixtures/Kdbx")

    private let password = "correct-horse-battery"

    private var fixtureFiles: [URL] {
        (try? FileManager.default.contentsOfDirectory(
            at: Self.fixturesDirectory, includingPropertiesForKeys: nil
        ))?.filter { $0.pathExtension == "kdbx" }.sorted { $0.lastPathComponent < $1.lastPathComponent } ?? []
    }

    private func credentials(_ name: String) throws -> KdbxReader.Credentials {
        if name == "kxc-keyfile.kdbx" {
            let keyFileData = try Data(contentsOf: Self.fixturesDirectory.appendingPathComponent("kxc-keyfile.keyx"))
            return try KdbxReader.Credentials(
                password: password,
                keyFileKey: try KdbxKeyFile.load(data: keyFileData)
            )
        }
        return try KdbxReader.Credentials(password: password)
    }

    func testCorpusDirectoryIsPopulated() {
        XCTAssertFalse(fixtureFiles.isEmpty, "Corpus directory empty — run scripts/generate-corpus.sh (gate must not silently pass)")
    }

    func testEveryFixtureReadsAndRoundTrips() throws {
        let files = fixtureFiles
        XCTAssertGreaterThanOrEqual(files.count, 10, "corpus shrank — regenerate via scripts/generate-corpus.sh")

        for file in files {
            let data = try Data(contentsOf: file)
            let name = file.lastPathComponent
            print("GATE-FILE:", name)
            let creds = try credentials(name)

            // (a) read succeeds
            let document = try KdbxReader.read(data, credentials: creds)
            // (b) semantic round trip (⟳-aware comparison, 01-03 harness).
            // Exception per FI-07: the 3.1 attachment fixture keeps its
            // binaries opaquely in Meta/Binaries (D-06, no 3.1 pool model
            // yet), so its entry refs dangle by construction — the 4.0
            // upgrade write must fail loudly rather than emit the silently
            // broken file it did before the ref validation existed.
            if name == "kxc-attachment.kdbx" {
                XCTAssertThrowsError(try KdbxWriter.write(document, credentials: creds)) { error in
                    XCTAssertEqual(error as? KdbxError, .malformedData, name)
                }
            } else {
                let rewritten = try KdbxWriter.write(document, credentials: creds)
                let reopened = try KdbxReader.read(rewritten, credentials: creds)
                SemanticKdbx.assertSemanticallyEqual(document, reopened)
            }
            // (c) wrong credentials fail
            XCTAssertThrowsError(try KdbxReader.read(data, credentials: try KdbxReader.Credentials(password: "definitely-wrong"))) { error in
                XCTAssertEqual(error as? KdbxError, .wrongCredentials, name)
            }
        }
    }

    func testExpectedContentPerFixture() throws {
        let expected: [String: (CorpusGateTests) throws -> Void] = [
            "kxc-default.kdbx": { gate in
                let doc = try gate.open("kxc-default.kdbx")
                let names = doc.root.allEntries().map(\.name)
                XCTAssertTrue(names.contains("GitHub"), "kxc-default: GitHub entry missing; got \(names)")
                XCTAssertTrue(names.contains("GitLab"), "kxc-default: GitLab entry missing")
                let github = doc.root.allEntries().first { $0.name == "GitHub" }
                XCTAssertEqual(github?.username, "alice", "kxc-default username")
                XCTAssertEqual(github?.url, "https://example.com", "kxc-default url")
                XCTAssertEqual(github?.password, "pw-github-1", "kxc-default password")
            },
            "kxc-history.kdbx": { gate in
                let doc = try gate.open("kxc-history.kdbx")
                let entry = try XCTUnwrap(doc.root.allEntries().first { $0.name == "RotatingSecret" })
                XCTAssertGreaterThanOrEqual(entry.historyCount, 1, "kxc-history revisions")
                XCTAssertEqual(entry.password, "secret-v2", "kxc-history current password")
            },
            "kxc-recyclebin.kdbx": { gate in
                let doc = try gate.open("kxc-recyclebin.kdbx")
                XCTAssertEqual(doc.meta.recycleBinEnabled, true, "kxc-recyclebin enabled")
                let names = doc.root.allEntries().map(\.name)
                XCTAssertTrue(names.contains("DoomedEntry"), "kxc-recyclebin removed entry preserved; got \(names)")
            },
            "kxc-attachment.kdbx": { gate in
                let doc = try gate.open("kxc-attachment.kdbx")
                if doc.version.major >= 4 {
                    XCTAssertEqual(doc.binaries.count, 1, "kxc-attachment pool")
                    let entry = try XCTUnwrap(doc.root.allEntries().first { $0.name == "WithFile" })
                    XCTAssertEqual(entry.attachments.count, 1, "kxc-attachment ref")
                    XCTAssertEqual(doc.binaries[entry.attachments[0].ref].content.count, 65536, "kxc-attachment size")
                } else {
                    // KDBX 3.1 stores binaries in Meta/Binaries — preserved
                    // opaquely (D-06) until a dedicated 3.1 model lands.
                    let hasOpaqueBinaries = doc.meta.unknownXml.contains { $0.name == "Binaries" }
                    XCTAssertTrue(hasOpaqueBinaries, "kxc-attachment: 3.1 Binaries must survive opaquely")
                }
            },
            "kxc-keyfile.kdbx": { gate in
                let doc = try gate.open("kxc-keyfile.kdbx")
                let names = doc.root.allEntries().map(\.name)
                XCTAssertTrue(names.contains("KeyfileEntry"), "kxc-keyfile entry; got \(names)")
            },
            "rv-argon2d.kdbx": { gate in try gate.assertRavenVaultEntry("rv-argon2d.kdbx") },
            "rv-aeskdf.kdbx": { gate in try gate.assertRavenVaultEntry("rv-aeskdf.kdbx") },
            "rv-chacha20.kdbx": { gate in try gate.assertRavenVaultEntry("rv-chacha20.kdbx") },
            "rv-nocompress.kdbx": { gate in try gate.assertRavenVaultEntry("rv-nocompress.kdbx") },
            "kxc-passkey.kdbx": { gate in try gate.assertPasskeyEntry("kxc-passkey.kdbx") },
            "rv-passkey.kdbx": { gate in try gate.assertPasskeyEntry("rv-passkey.kdbx") },
        ]

        for file in fixtureFiles {
            if let check = expected[file.lastPathComponent] {
                try check(self)
            }
        }
    }

    // MARK: - Entry accessors (semantic, name-based)

    func open(_ name: String) throws -> KdbxDocument {
        let data = try Data(contentsOf: Self.fixturesDirectory.appendingPathComponent(name))
        return try KdbxReader.read(data, credentials: try credentials(name))
    }

    func assertRavenVaultEntry(_ name: String) throws {
        let doc = try open(name)
        let entry = try XCTUnwrap(doc.root.allEntries().first { $0.name == "RavenVaultEntry" }, name)
        XCTAssertEqual(entry.username, "rv-user", name)
        XCTAssertEqual(entry.password, "pw-rv-secret", name)
    }

    /// kxc-passkey.kdbx / rv-passkey.kdbx (02-01, D-03): the KeePassXC
    /// passkey layout reads back as the fixed synthetic credential with the
    /// protection layout intact. Values mirror MANIFEST.md.
    func assertPasskeyEntry(_ name: String) throws {
        let doc = try open(name)
        let entry = try XCTUnwrap(doc.root.allEntries().first { $0.name == "RavenTest (Passkey)" }, name)

        let credential = try XCTUnwrap(try KdbxPasskey.read(from: entry), name)
        XCTAssertEqual(credential, PasskeyTests.fixtureCredential(), name)

        // Protected attribute layout survived on disk (T-01-01).
        func isProtected(_ key: String) -> Bool {
            entry.strings.first { $0.key == key }?.protected ?? false
        }
        XCTAssertTrue(isProtected(KdbxPasskey.credentialIDKey), "\(name): CREDENTIAL_ID protected")
        XCTAssertTrue(isProtected(KdbxPasskey.privateKeyPEMKey), "\(name): PRIVATE_KEY_PEM protected")
        XCTAssertTrue(isProtected(KdbxPasskey.userHandleKey), "\(name): USER_HANDLE protected")
        XCTAssertFalse(isProtected(KdbxPasskey.usernameKey), name)
        XCTAssertFalse(isProtected(KdbxPasskey.relyingPartyKey), name)

        // FLAG_BE="1"/FLAG_BS="0" must be read distinctly (absent-default not in play).
        XCTAssertTrue(credential.backupEligibility, name)
        XCTAssertFalse(credential.backupState, "\(name): FLAG_BS=0 must read false")
    }
}
