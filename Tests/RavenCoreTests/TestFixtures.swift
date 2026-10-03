import CryptoKit
import XCTest
@testable import RavenCore

/// Canonical serialized vault fixtures. These files pin the formatVersion 1
/// wire format: every future change to VaultDocument/VaultHeader encoding must
/// keep these files unlockable (see 01-CONTEXT.md D-04 / CONCERNS.md fixtures).
enum TestFixtures {

    /// Absolute path of the committed fixtures directory (Tests/Fixtures/RavenVault).
    static var ravenVaultDirectory: String {
        packageRoot.appending("/Tests/Fixtures/RavenVault")
    }

    /// Absolute path of the package root — the directory containing Package.swift.
    /// Located by walking up from this file, so the package tests identically inside
    /// the monorepo (…/Packages/RavenCore) and as a standalone published repository.
    static var packageRoot: String {
        var dir = (#filePath as NSString).deletingLastPathComponent
        while dir != "/" {
            if FileManager.default.fileExists(atPath: dir + "/Package.swift") { return dir }
            dir = (dir as NSString).deletingLastPathComponent
        }
        preconditionFailure("Package.swift not found above \(#filePath)")
    }

    /// Absolute path of the repository root that holds the public `Docs/` tree
    /// (published format vectors). In the monorepo that is two levels above the
    /// package; in a standalone checkout it is the package root itself.
    static var repoRoot: String {
        let package = packageRoot
        if FileManager.default.fileExists(atPath: package + "/Docs/TEST-VECTORS") { return package }
        let monorepo = (package as NSString).deletingLastPathComponent
        let candidate = (monorepo as NSString).deletingLastPathComponent
        if FileManager.default.fileExists(atPath: candidate + "/Docs/TEST-VECTORS") { return candidate }
        preconditionFailure("Docs/TEST-VECTORS not found at \(package) or \(candidate)")
    }

    static func loadV1Fixture(_ name: String) throws -> Data {
        let url = URL(fileURLWithPath: ravenVaultDirectory).appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: url.path) else {
            XCTFail("Missing canonical fixture \(name) — run once with GENERATE_FIXTURES=1")
            throw NSError(domain: "TestFixtures", code: 1)
        }
        return try Data(contentsOf: url)
    }

    /// SHA-256 of `data` as lowercase hex — the pin format for fixture fidelity.
    static func sha256Hex(_ data: Data) -> String {
        Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
    }
}

/// One-time generation of the canonical v2 baseline fixture from the *current*
/// engine (Argon2id, formatVersion 2) — 04-01 fixture-first discipline: this
/// baseline is minted BEFORE the organization-metadata extension (url/tags/
/// folderID/folders) touches any format code, so the extension always has a
/// pre-change v2 wire format to prove decode compatibility against.
///   GENERATE_FIXTURES=1 swift test --filter CanonicalFixtureGenerationTests
extension CanonicalFixtureGenerationTests {

    func testGenerateCanonicalV2BaselineFixture() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_FIXTURES"] == "1" else {
            throw XCTSkip("Set GENERATE_FIXTURES=1 to (re)generate canonical v2 baseline fixture")
        }

        let passphrase = "correct horse battery staple"
        let vault = try VaultService.create(passphrase: passphrase)
        _ = try vault.add(.password, level: .auto, payload: RecordPayload(
            title: "GitHub", username: "u@example.com", password: "hunter2!", notes: "dev account"))
        _ = try vault.add(.totp, level: .auto, payload: RecordPayload(
            title: "SSO portal", username: "ops", totpSecret: "JBSWY3DPEHPK3PXP"))
        let archivedId = try vault.add(.secureNote, level: .custom, payload: RecordPayload(
            title: "Recovery note", notes: "pre-extension archived record"))
        try vault.archive(id: archivedId)

        let data = try vault.serializedDocument()
        let dir = URL(fileURLWithPath: TestFixtures.ravenVaultDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try data.write(to: dir.appendingPathComponent("v2-baseline.json"))

        let doc = try JSONDecoder().decode(VaultDocument.self, from: data)
        XCTAssertEqual(doc.header.formatVersion, 2, "v2 baseline must pin formatVersion 2")
        XCTAssertEqual(doc.header.kdfAlgorithm, VaultKDF.argon2id, "v2 baseline must pin Argon2id")
        print("v2-baseline.json sha256 = \(TestFixtures.sha256Hex(data))")
    }
}

/// Fidelity pins for the canonical fixtures (always-on). The v2 baseline is
/// the pre-extension formatVersion-2 wire format — every future encoding
/// change must keep it byte-identical or gate a deliberate re-pin (04-01
/// fixture-first discipline).
final class CanonicalFixturePinTests: XCTestCase {

    func testV2BaselineFixtureIsPinned() throws {
        let data = try TestFixtures.loadV1Fixture("v2-baseline.json")
        XCTAssertEqual(
            TestFixtures.sha256Hex(data),
            "549a65f270bf512d96d434dc5063eb168fdd754786bc585497c529b5211819b5",
            "v2-baseline.json changed — a deliberate format re-pin must accompany this diff")
    }

    /// The v2 baseline unlocks and round-trips through the current model —
    /// the extension compatibility anchor (records survive, archived kept).
    func testV2BaselineUnlocksAndCarriesRecords() throws {
        let data = try TestFixtures.loadV1Fixture("v2-baseline.json")
        let vault = try VaultService.unlock(serializedDocument: data, passphrase: "correct horse battery staple")
        let records = try vault.records()
        XCTAssertEqual(records.count, 3)
        XCTAssertEqual(records.filter(\.isArchived).count, 1)
        XCTAssertTrue(vault.verifyChain())
    }
}

/// One-time generation of the canonical v1 fixtures from the *current* engine.
/// Opt-in so ordinary `swift test` runs never rewrite them:
///   GENERATE_FIXTURES=1 swift test --filter CanonicalFixtureGenerationTests
final class CanonicalFixtureGenerationTests: XCTestCase {

    func testGenerateCanonicalV1Fixtures() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_FIXTURES"] == "1" else {
            throw XCTSkip("Set GENERATE_FIXTURES=1 to (re)generate canonical v1 fixtures")
        }

        let passphrase = "correct horse battery staple"

        // (a) minimal: empty-log vault
        let minimal = try VaultService.createLegacyPBKDF2(passphrase: passphrase, iterations: 600_000)
        let minimalData = try minimal.serializedDocument()

        // (b) with records: ≥3 records, one .custom level, one archived, pre-compaction
        let withRecords = try VaultService.createLegacyPBKDF2(passphrase: passphrase, iterations: 600_000)
        _ = try withRecords.add(.password, level: .auto, payload: RecordPayload(
            title: "GitHub", username: "u@example.com", password: "hunter2!", notes: "dev account"))
        _ = try withRecords.add(.seedPhrase, level: .custom, payload: RecordPayload(
            title: "BTC cold", username: "", password: "", notes: "",
            seedPhrase: ["abandon", "ability", "able", "about", "absent"]))
        let droppedId = try withRecords.add(.password, level: .auto, payload: RecordPayload(
            title: "Dropped", username: "old@example.com", password: "legacy", notes: ""))
        try withRecords.archive(id: droppedId)
        // Serialize BEFORE compaction so the fixture pins the archived-entry encoding too.

        let dir = URL(fileURLWithPath: TestFixtures.ravenVaultDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try minimalData.write(to: dir.appendingPathComponent("v1-minimal.json"))
        try withRecords.serializedDocument().write(to: dir.appendingPathComponent("v1-with-records.json"))

        // Assert fixture shape: formatVersion 1 + PBKDF2 600k
        for name in ["v1-minimal.json", "v1-with-records.json"] {
            let data = try Data(contentsOf: dir.appendingPathComponent(name))
            let doc = try JSONDecoder().decode(VaultDocument.self, from: data)
            XCTAssertEqual(doc.header.formatVersion, 1, name)
            XCTAssertEqual(doc.header.kdfIterations, 600_000, name)
        }
    }
}
