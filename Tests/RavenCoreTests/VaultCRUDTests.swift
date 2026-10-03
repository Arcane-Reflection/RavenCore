import XCTest
@testable import RavenCore

/// Record CRUD + organization semantics (04-CONTEXT D-01/D-02/D-03): same-id
/// supersede-on-edit, archive-all-versions, unarchive, folder tree, and the
/// organization-metadata wire-format extension's decode compatibility.
final class VaultCRUDTests: XCTestCase {

    private let passphrase = "correct horse battery staple"

    @discardableResult
    private func makeVault() throws -> VaultService {
        try VaultService.create(passphrase: passphrase)
    }

    // MARK: - Chain verify (261003-mk7 sixth pass: tamper evidence enforced)

    /// A single flipped byte in the log payload (post-auth tamper) must fail
    /// unlock with corruptDocument — the GCM envelope only authenticates the
    /// key wrap; the hash chain + header pairing is the log's own gate.
    func testTamperedLogEntryFailsUnlock() throws {
        let vault = try makeVault()
        try vault.add(.password, level: .auto, payload: RecordPayload(title: "T", password: "p"))
        var data = try vault.serializedDocument()

        // Flip one byte deep inside the document (log region — past header).
        let index = data.index(data.endIndex, offsetBy: -3)
        data[index] ^= 0xFF

        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: data, passphrase: passphrase)) { error in
            XCTAssertEqual(error as? VaultError, .corruptDocument)
        }
    }

    /// A desynced header.headHash (log truncated or header rewritten) fails
    /// the pairing half of the gate.
    func testDesyncedHeadHashFailsUnlock() throws {
        let vault = try makeVault()
        try vault.add(.password, level: .auto, payload: RecordPayload(title: "T", password: "p"))
        var document = try JSONDecoder().decode(VaultDocument.self, from: vault.serializedDocument())
        document.log.entries.removeLast() // truncate the log under the pinned head
        let tampered = try JSONEncoder().encode(document)

        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: tampered, passphrase: passphrase)) { error in
            XCTAssertEqual(error as? VaultError, .corruptDocument)
        }
    }

    /// Wrong passphrase keeps error precedence over the integrity gate — the
    /// tamper gate adds no oracle (the GCM check runs first).
    func testWrongPassphrasePrecedesChainGate() throws {
        let vault = try makeVault()
        try vault.add(.password, level: .auto, payload: RecordPayload(title: "T", password: "p"))
        let data = try vault.serializedDocument()
        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: data, passphrase: "wrong")) { error in
            XCTAssertEqual(error as? VaultError, .wrongPassphrase)
        }
    }

    /// The legitimate mutation→save cycle keeps header.headHash paired
    /// without the removed serializedDocument restamp — the gate must never
    /// reject a vault the engine itself wrote.
    func testMutatedVaultSerializesWithPairedHeadHash() throws {
        let vault = try makeVault()
        try vault.add(.password, level: .auto, payload: RecordPayload(title: "A", password: "p1"))
        try vault.add(.password, level: .auto, payload: RecordPayload(title: "B", password: "p2"))
        try vault.archive(id: try vault.records().first { $0.payload.title == "A" }!.id)

        let data = try vault.serializedDocument()
        let reopened = try VaultService.unlock(serializedDocument: data, passphrase: passphrase)
        // records() includes archived rows (D-05) — A survives, still archived.
        let records = try reopened.records()
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records.first { $0.payload.title == "A" }?.isArchived, true)
    }

    // MARK: - Extension decode compatibility (fixture-first anchor)

    /// The PRE-extension canonical v2 baseline decodes under the extended
    /// model with every new field nil — old vaults open unchanged (T-04-02).
    func testV2BaselineDecodesWithExtensionFieldsNil() throws {
        let data = try TestFixtures.loadV1Fixture("v2-baseline.json")
        let vault = try VaultService.unlock(serializedDocument: data, passphrase: passphrase)
        let records = try vault.records()
        XCTAssertEqual(records.count, 3)
        for record in records {
            XCTAssertNil(record.tags)
            XCTAssertNil(record.folderID)
            XCTAssertNil(record.payload.url)
        }
        XCTAssertNil(try unlockedDocumentFolders(of: vault))
    }

    private func unlockedDocumentFolders(of vault: VaultService) throws -> [Folder]? {
        try JSONDecoder().decode(VaultDocument.self, from: vault.serializedDocument()).folders
    }

    // MARK: - Update (same-id supersede)

    func testUpdateSupersedesWithSameID() throws {
        let vault = try makeVault()
        let clock = TestClock(start: 1_000)
        let id = try vault.add(.password, level: .auto, payload: RecordPayload(
            title: "GitHub", username: "u@example.com", password: "one"), at: clock())
        try vault.update(id: id, type: .password, level: .auto, payload: RecordPayload(
            title: "GitHub", username: "u@new.example.com", password: "two", url: "https://github.com"),
            tags: ["dev"], at: clock())

        let records = try vault.records()
        XCTAssertEqual(records.count, 1, "same-id versions dedupe to one record")
        XCTAssertEqual(records[0].id, id)
        XCTAssertEqual(records[0].payload.password, "two", "newest version wins")
        XCTAssertEqual(records[0].payload.url, "https://github.com")
        XCTAssertEqual(records[0].tags, ["dev"])
        XCTAssertTrue(vault.verifyChain(), "supersede keeps the chain intact")
    }

    func testUpdateUnknownIDThrowsRecordNotFound() throws {
        let vault = try makeVault()
        XCTAssertThrowsError(try vault.update(
            id: UUID(), type: .password, level: .auto, payload: RecordPayload(title: "x"))) { error in
            XCTAssertEqual(error as? VaultError, .recordNotFound)
        }
    }

    func testUpdateReactivatesArchivedRecordExplicitly() throws {
        let vault = try makeVault()
        let clock = TestClock(start: 1_000)
        let id = try vault.add(.secureNote, level: .auto, payload: RecordPayload(title: "n"), at: clock())
        try vault.archive(id: id)
        XCTAssertTrue(try vault.records().first!.isArchived)
        // Editing explicitly re-materializes an active version (UI only edits
        // active records; the engine permits the restore-via-edit path).
        try vault.update(id: id, type: .secureNote, level: .auto, payload: RecordPayload(title: "n2"), at: clock())
        let active = try vault.activeRecords()
        XCTAssertEqual(active.count, 1)
        XCTAssertEqual(active[0].payload.title, "n2")
    }

    // MARK: - Archive all versions / unarchive

    func testArchiveRemovesEveryVersionOfID() throws {
        let vault = try makeVault()
        let clock = TestClock(start: 1_000)
        let id = try vault.add(.password, level: .auto, payload: RecordPayload(title: "v1"), at: clock())
        try vault.update(id: id, type: .password, level: .auto, payload: RecordPayload(title: "v2"), at: clock())
        try vault.update(id: id, type: .password, level: .auto, payload: RecordPayload(title: "v3"), at: clock())

        try vault.archive(id: id)
        XCTAssertTrue(try vault.activeRecords().isEmpty, "no version may stay active (T-04-03)")
        let archived = try vault.records().filter(\.isArchived)
        XCTAssertEqual(archived.count, 1, "archived versions dedupe to one record")
        XCTAssertEqual(archived[0].payload.title, "v3")
        // Re-archiving an already-archived record is a typed no-op at the
        // service boundary (idempotent at the log level).
        XCTAssertThrowsError(try vault.archive(id: id)) { error in
            XCTAssertEqual(error as? VaultError, .recordNotFound)
        }
    }

    func testUnarchiveRestoresRecord() throws {
        let vault = try makeVault()
        let clock = TestClock(start: 1_000)
        let id = try vault.add(.password, level: .auto, payload: RecordPayload(title: "keep"), at: clock())
        try vault.update(id: id, type: .password, level: .auto, payload: RecordPayload(title: "keep2"), at: clock())
        try vault.archive(id: id)
        try vault.unarchive(id: id)

        let active = try vault.activeRecords()
        XCTAssertEqual(active.count, 1)
        XCTAssertEqual(active[0].payload.title, "keep2")
        XCTAssertFalse(active[0].isArchived)

        XCTAssertThrowsError(try vault.unarchive(id: UUID())) { error in
            XCTAssertEqual(error as? VaultError, .recordNotFound)
        }
    }

    // MARK: - Folder organization (D-02)

    func testFolderCRUDLifecycle() throws {
        let vault = try makeVault()
        let parentId = try vault.addFolder(name: "Work")
        let childId = try vault.addFolder(name: "Finance", parentID: parentId)
        XCTAssertEqual(try vault.folders().count, 2)

        try vault.renameFolder(id: childId, to: "Banking")
        XCTAssertEqual(try vault.folders().first(where: { $0.id == childId })?.name, "Banking")

        // Sibling duplicate / empty name / unknown parent rejected typed.
        XCTAssertThrowsError(try vault.addFolder(name: "Banking", parentID: parentId)) { error in
            XCTAssertEqual(error as? VaultError, .duplicateFolderName)
        }
        XCTAssertThrowsError(try vault.addFolder(name: "   ")) { error in
            XCTAssertEqual(error as? VaultError, .invalidFolderName)
        }
        XCTAssertThrowsError(try vault.addFolder(name: "x", parentID: UUID())) { error in
            XCTAssertEqual(error as? VaultError, .folderNotFound)
        }
        // Duplicate names collide only within the same sibling group: renaming
        // "Banking" to root's "Work" is legal, but a second child collides.
        _ = try vault.addFolder(name: "Notes", parentID: parentId)
        try vault.renameFolder(id: childId, to: "Work") // different group — legal
        let notesId = try vault.folders().first(where: { $0.name == "Notes" })!.id
        XCTAssertThrowsError(try vault.renameFolder(id: notesId, to: "Work")) { error in
            XCTAssertEqual(error as? VaultError, .duplicateFolderName)
        }

        // A folder holding records cannot be deleted; emptied, it can.
        let clock = TestClock(start: 1_000)
        let id = try vault.add(.password, level: .auto, payload: RecordPayload(title: "in folder"), folderID: childId, at: clock())
        XCTAssertThrowsError(try vault.deleteFolder(id: childId)) { error in
            XCTAssertEqual(error as? VaultError, .folderNotEmpty)
        }
        try vault.archive(id: id) // archived versions still pin the folder
        XCTAssertThrowsError(try vault.deleteFolder(id: childId)) { error in
            XCTAssertEqual(error as? VaultError, .folderNotEmpty)
        }
        try vault.update(id: id, type: .password, level: .auto, payload: RecordPayload(title: "moved"), at: clock())
        try vault.deleteFolder(id: childId)
        // Parent still holds "Notes" until it is removed too.
        try vault.deleteFolder(id: notesId)
        try vault.deleteFolder(id: parentId)
        XCTAssertTrue(try vault.folders().isEmpty)
    }

    func testFolderWithChildFoldersCannotBeDeleted() throws {
        let vault = try makeVault()
        let parentId = try vault.addFolder(name: "Parent")
        _ = try vault.addFolder(name: "Child", parentID: parentId)
        XCTAssertThrowsError(try vault.deleteFolder(id: parentId)) { error in
            XCTAssertEqual(error as? VaultError, .folderNotEmpty)
        }
    }

    func testUnknownFolderOperationsThrow() throws {
        let vault = try makeVault()
        XCTAssertThrowsError(try vault.renameFolder(id: UUID(), to: "x")) { error in
            XCTAssertEqual(error as? VaultError, .folderNotFound)
        }
        XCTAssertThrowsError(try vault.deleteFolder(id: UUID())) { error in
            XCTAssertEqual(error as? VaultError, .folderNotFound)
        }
    }

    // MARK: - Wire format travel

    func testOrganizationMetadataTravelsWithFile() throws {
        let vault = try makeVault()
        let clock = TestClock(start: 1_000)
        let folderId = try vault.addFolder(name: "Travel")
        let id = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "r", password: "p", url: "https://r.example"),
            tags: ["a", "b"], folderID: folderId, at: clock())

        let data = try vault.serializedDocument()
        let reopened = try VaultService.unlock(serializedDocument: data, passphrase: passphrase)
        let record = try reopened.records().first(where: { $0.id == id })
        XCTAssertEqual(record?.tags, ["a", "b"])
        XCTAssertEqual(record?.folderID, folderId)
        XCTAssertEqual(record?.payload.url, "https://r.example")
        XCTAssertEqual(try reopened.folders().first?.name, "Travel")
        XCTAssertTrue(reopened.verifyChain())
    }
}

/// Opt-in generation of the POST-extension canonical fixture (extended wire
/// format with url/tags/folderID/folders populated):
///   GENERATE_FIXTURES=1 swift test --filter VaultCRUDTests/testGenerateExtendedFixture
extension VaultCRUDTests {

    func testGenerateExtendedFixture() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_FIXTURES"] == "1" else {
            throw XCTSkip("Set GENERATE_FIXTURES=1 to (re)generate the extended v2 fixture")
        }
        let vault = try makeVault()
        let folderId = try vault.addFolder(name: "Work")
        let childId = try vault.addFolder(name: "Finance", parentID: folderId)
        _ = try vault.add(.password, level: .auto,
                          payload: RecordPayload(title: "GitHub", username: "u@example.com",
                                                 password: "hunter2!", notes: "dev account",
                                                 url: "https://github.com"),
                          tags: ["dev", "web"], folderID: folderId)
        _ = try vault.add(.totp, level: .auto,
                          payload: RecordPayload(title: "SSO", totpSecret: "JBSWY3DPEHPK3PXP"),
                          folderID: childId)
        let archivedId = try vault.add(.seedPhrase, level: .custom,
                                       payload: RecordPayload(title: "Old seed",
                                                              seedPhrase: ["abandon", "ability", "able"]))
        try vault.archive(id: archivedId)
        let data = try vault.serializedDocument()
        let dir = URL(fileURLWithPath: TestFixtures.ravenVaultDirectory)
        try data.write(to: dir.appendingPathComponent("v2-extended.json"))
        print("v2-extended.json sha256 = \(TestFixtures.sha256Hex(data))")
    }

    func testExtendedFixtureIsPinned() throws {
        let data = try TestFixtures.loadV1Fixture("v2-extended.json")
        XCTAssertEqual(
            TestFixtures.sha256Hex(data),
            "4e24085a1ddcf9930c3237a5da64d53732995641427334b736a5cec538ba63bd",
            "v2-extended.json changed — a deliberate format re-pin must accompany this diff")
    }
}

/// Monotonic test clock (`at date:` injection points on add/update).
struct TestClock {
    private let start: TimeInterval
    init(start: TimeInterval) { self.start = start }
    func callAsFunction() -> Date { Date(timeIntervalSince1970: start) }
}
