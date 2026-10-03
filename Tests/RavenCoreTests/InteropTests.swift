import XCTest
@testable import RavenCore

/// kdbx⇄native interop mapper tests (VAULT-04 engine half, 05-CONTEXT
/// D-02/D-04): RecordEnvelope attachments decode compatibility against every
/// canonical fixture, the v2-attachments fixture pin, and the five-library
/// KeePassXC corpus import assertions (kxc-default / kxc-history /
/// kxc-attachment / kxc-recyclebin / kxc-passkey). Expected values mirror
/// Tests/Fixtures/Kdbx/MANIFEST.md.
final class InteropTests: XCTestCase {

    static let corpusDirectory: URL = URL(fileURLWithPath: TestFixtures.packageRoot)
        .appendingPathComponent("Tests/Fixtures/Kdbx")

    /// Uniform corpus password (MANIFEST.md).
    private let corpusPassword = "correct-horse-battery"
    /// Uniform RavenVault fixture passphrase (TestFixtures generation tests).
    private let fixturePassword = "correct horse battery staple"

    private func openCorpus(_ name: String) throws -> KdbxDocument {
        let data = try Data(contentsOf: Self.corpusDirectory.appendingPathComponent(name))
        return try KdbxReader.read(data, credentials: .init(password: corpusPassword))
    }

    // MARK: - Attachments decode compatibility (05-CONTEXT D-04)

    /// Every pre-extension canonical fixture still unlocks and decodes under
    /// the extended model. `VaultService.unlock` decodes every log envelope
    /// through the extended `RecordEnvelope` decoder — the fixtures having no
    /// `attachments` key proves the additive optional decodes nil, and the
    /// chain verifies prove nothing else moved.
    func testPreExtensionFixturesDecodeWithAttachmentsNil() throws {
        let expectedRecords = [
            "v1-minimal.json": 0,
            "v1-with-records.json": 3,
            "v2-baseline.json": 3,
            "v2-extended.json": 3,
        ]
        for (name, expectedCount) in expectedRecords {
            let data = try TestFixtures.loadV1Fixture(name)
            let vault = try VaultService.unlock(serializedDocument: data, passphrase: fixturePassword)
            XCTAssertTrue(vault.verifyChain(), name)
            let records = try vault.records()
            XCTAssertEqual(records.count, expectedCount, name)
            for record in records {
                XCTAssertNil(record.attachments, "\(name): pre-extension records carry no attachments")
            }
        }
    }

    /// The attachment extension does not touch the existing wire-format keys:
    /// absent optionals are omitted, and formatVersion stays 2 (no bump).
    func testAttachmentEnvelopeOmitsAbsentOptionalKey() throws {
        let vault = try VaultService.create(passphrase: fixturePassword)
        _ = try vault.add(.password, level: .auto, payload: RecordPayload(title: "No attachment"))
        let data = try vault.serializedDocument()
        let json = String(decoding: data, as: UTF8.self)
        XCTAssertFalse(json.contains("attachments"), "absent attachments must be omitted from the wire format")
        XCTAssertFalse(json.contains("contentType"), "absent contentType must be omitted from the wire format")
        let document = try JSONDecoder().decode(VaultDocument.self, from: data)
        XCTAssertEqual(document.header.formatVersion, 2, "formatVersion must stay 2 (no bump)")
    }

    /// Attachments survive the full serialize → unlock → records cycle with
    /// bytes intact (the envelope-level inline storage contract, D-04).
    func testAttachmentsRoundTripThroughSerializedDocument() throws {
        let vault = try VaultService.create(passphrase: fixturePassword)
        let attachment = RecordAttachment(
            id: UUID(), name: "kit.txt", contentType: "text/plain",
            data: Data("attachment payload".utf8))
        _ = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "Carrier"), attachments: [attachment])
        let serialized = try vault.serializedDocument()

        let reopened = try VaultService.unlock(serializedDocument: serialized, passphrase: fixturePassword)
        let records = try reopened.records()
        XCTAssertEqual(records[0].attachments, [attachment], "inline bytes must round-trip exactly")
    }

    // MARK: - v2-attachments canonical fixture (fixture-first, D-04)

    /// One-time minting of the canonical attachments fixture (1 small
    /// attachment carried across a superseding version). Opt-in so ordinary
    /// runs never rewrite it:
    ///   GENERATE_FIXTURES=1 swift test --filter InteropTests/testGenerateAttachmentsFixture
    func testGenerateAttachmentsFixture() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_FIXTURES"] == "1" else {
            throw XCTSkip("Set GENERATE_FIXTURES=1 to (re)generate the v2-attachments fixture")
        }

        let vault = try VaultService.create(passphrase: fixturePassword)
        let attachment = RecordAttachment(
            id: UUID(), name: "recovery-kit.txt", contentType: "text/plain",
            data: Data("ravenvault synthetic attachment payload\n".utf8))
        let id = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "With Attachment", username: "u@example.com",
                                   password: "hunter2!", notes: "carries one inline attachment"),
            attachments: [attachment])
        // The superseding version keeps the attachment — versioned content
        // riding the envelope (D-04), pinned across both log entries.
        try vault.update(
            id: id, type: .password, level: .auto,
            payload: RecordPayload(title: "With Attachment", username: "u@example.com",
                                   password: "hunter2-updated!", notes: "attachment kept in v2"),
            attachments: [attachment])

        let data = try vault.serializedDocument()
        let dir = URL(fileURLWithPath: TestFixtures.ravenVaultDirectory)
        try data.write(to: dir.appendingPathComponent("v2-attachments.json"))
        let document = try JSONDecoder().decode(VaultDocument.self, from: data)
        XCTAssertEqual(document.header.formatVersion, 2, "v2-attachments pins formatVersion 2")
        print("v2-attachments.json sha256 = \(TestFixtures.sha256Hex(data))")
    }

    /// Pin of the minted fixture bytes (filled from the generation run's
    /// printed hash — same discipline as v2-baseline/v2-extended).
    static let attachmentsFixtureSHA256 = "bdfa34c3c0cd9ec14a3548776cbed3221a9e2efa41d524abadbd4f6faa75f6e3"

    func testAttachmentsFixtureIsPinned() throws {
        let data = try TestFixtures.loadV1Fixture("v2-attachments.json")
        XCTAssertEqual(
            TestFixtures.sha256Hex(data),
            Self.attachmentsFixtureSHA256,
            "v2-attachments.json changed — a deliberate format re-pin must accompany this diff")
    }

    /// The pinned attachments fixture unlocks with attachment bytes intact.
    func testAttachmentsFixtureCarriesInlineBytes() throws {
        let data = try TestFixtures.loadV1Fixture("v2-attachments.json")
        let vault = try VaultService.unlock(serializedDocument: data, passphrase: fixturePassword)
        let records = try vault.records()
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].attachments?.count, 1)
        XCTAssertEqual(records[0].attachments?.first?.name, "recovery-kit.txt")
        XCTAssertEqual(records[0].attachments?.first?.data, Data("ravenvault synthetic attachment payload\n".utf8))
        XCTAssertTrue(vault.verifyChain())
    }

    // MARK: - Corpus import: kxc-default

    func testImportKxcDefault() throws {
        let content = try KdbxVaultMapper.nativeVault(from: try openCorpus("kxc-default.kdbx"))

        // Root-only database: two entries, no subgroups → no folders.
        XCTAssertEqual(content.summary.recordCount, 2)
        XCTAssertEqual(content.folders.count, 0)
        XCTAssertTrue(content.summary.skippedCounts.isEmpty, "kxc-default drops nothing; got \(content.summary.skippedCounts)")

        let github = try XCTUnwrap(content.records.first { $0.payload.title == "GitHub" })
        XCTAssertEqual(github.type, .password, "v1 imports are uniformly password records")
        XCTAssertEqual(github.level, .auto)
        XCTAssertEqual(github.payload.username, "alice")
        XCTAssertEqual(github.payload.password, "pw-github-1")
        XCTAssertEqual(github.payload.url, "https://example.com")
        XCTAssertEqual(github.payload.notes, "synthetic entry one")
        XCTAssertNil(github.payload.totpSecret)
        XCTAssertTrue(github.historyVersions.isEmpty)
        XCTAssertFalse(github.isArchived)

        let gitlab = try XCTUnwrap(content.records.first { $0.payload.title == "GitLab" })
        XCTAssertEqual(gitlab.payload.username, "bob")
        XCTAssertEqual(gitlab.payload.password, "", "GitLab was added without a password (nil → empty)")
    }

    // MARK: - Corpus import: kxc-history

    func testImportKxcHistory() throws {
        let document = try openCorpus("kxc-history.kdbx")
        let entry = try XCTUnwrap(document.root.allEntries().first { $0.name == "RotatingSecret" })
        let content = try KdbxVaultMapper.nativeVault(from: document)

        XCTAssertEqual(content.records.count, 1)
        let record = try XCTUnwrap(content.records.first)
        // Version chain = historyCount + 1 (MANIFEST: 2 revisions).
        XCTAssertEqual(entry.historyCount, 2)
        XCTAssertEqual(record.historyVersions.count, 2, "history maps to the same-id version chain")
        XCTAssertEqual(content.summary.versionCount, 3)

        // Oldest → newest: v1 secret, v2 secret, current v3 secret.
        XCTAssertEqual(record.historyVersions[0].payload.password, "secret-v1")
        XCTAssertEqual(record.historyVersions[1].payload.password, "secret-v2")
        XCTAssertEqual(record.payload.password, "secret-v2")
        XCTAssertEqual(record.payload.notes, "rotated twice")
        // Version timestamps strictly increase (KdbxTimes-driven chain).
        XCTAssertLessThan(record.historyVersions[0].at, record.historyVersions[1].at)
    }

    // MARK: - Corpus import: kxc-attachment (KDBX 3.1)

    /// kxc-attachment.kdbx is a KDBX **3.1** file: its binary pool rides
    /// Meta/Binaries opaquely (D-06), so the entry's binary reference dangles
    /// in the unified 4.x model by construction. The entry still imports —
    /// without the attachment — and the loss is counted, never silent.
    func testImportKxcAttachment31OpaquePoolIsCounted() throws {
        let document = try openCorpus("kxc-attachment.kdbx")
        XCTAssertEqual(document.version.major, 3, "fixture stays 3.1 (regression lock for this path)")
        let entry = try XCTUnwrap(document.root.allEntries().first { $0.name == "WithFile" })
        XCTAssertEqual(entry.binaries.count, 1)

        let content = try KdbxVaultMapper.nativeVault(from: document)
        XCTAssertEqual(content.summary.recordCount, 1)
        let record = try XCTUnwrap(content.records.first)
        XCTAssertEqual(record.payload.title, "WithFile")
        XCTAssertNil(record.attachments, "unreachable bytes must not fabricate an attachment")
        XCTAssertEqual(content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.unresolvedAttachments], 1)
    }

    // MARK: - Corpus import: rv-attachment4 (4.x byte fidelity)

    /// The engine-written 4.x attachment corpus fixture pins the byte-level
    /// import contract kxc-attachment (3.1, opaque pool) cannot: attachment
    /// name and content survive the pool indirection exactly.
    func testImportRvAttachment4CarriesBytes() throws {
        let document = try openCorpus("rv-attachment4.kdbx")
        let entry = try XCTUnwrap(document.root.allEntries().first { $0.name == "WithFile4" })
        XCTAssertEqual(document.binaries.count, 1)

        let content = try KdbxVaultMapper.nativeVault(from: document)
        XCTAssertEqual(content.summary.recordCount, 1)
        XCTAssertEqual(content.summary.attachmentCount, 1)
        XCTAssertTrue(content.summary.skippedCounts.isEmpty)
        let record = try XCTUnwrap(content.records.first)
        XCTAssertEqual(record.attachments?.count, 1)
        let attachment = try XCTUnwrap(record.attachments?.first)
        XCTAssertEqual(attachment.name, entry.binaries[0].key)
        XCTAssertEqual(attachment.data, document.binaries[entry.binaries[0].ref].content)
        XCTAssertEqual(attachment.data.count, 65536)
    }

    // MARK: - Corpus import: kxc-recyclebin

    func testImportKxcRecycleBin() throws {
        let document = try openCorpus("kxc-recyclebin.kdbx")
        XCTAssertEqual(document.meta.recycleBinEnabled, true)
        let content = try KdbxVaultMapper.nativeVault(from: document)

        XCTAssertEqual(content.summary.recordCount, 1)
        let doomed = try XCTUnwrap(content.records.first { $0.payload.title == "DoomedEntry" })
        XCTAssertTrue(doomed.isArchived, "recycle-bin subtree maps to the archived state (D-02)")
        // The recycle-bin group itself is a top-level folder in the tree.
        XCTAssertEqual(content.folders.count, 1)
        XCTAssertNil(content.folders[0].parentID)
        XCTAssertEqual(doomed.folderID, content.folders[0].id, "record keeps its group placement")
    }

    // MARK: - Corpus import: kxc-passkey

    /// 06-CONTEXT D-09 close-out: the passkey attributes are consumed into
    /// `RecordPayload.passkey` — only a malformed passkey entry keeps
    /// counting under `passkeyAttributes` (that path is covered in
    /// RecordPayloadPasskeyTests).
    func testImportKxcPasskeyConsumesAttributesIntoPayload() throws {
        let content = try KdbxVaultMapper.nativeVault(from: try openCorpus("kxc-passkey.kdbx"))

        // The entry imports as a passkey-bearing record…
        XCTAssertEqual(content.summary.recordCount, 1)
        let record = try XCTUnwrap(content.records.first)
        XCTAssertEqual(record.payload.title, "RavenTest (Passkey)")
        XCTAssertEqual(record.payload.username, "alice@example.com")
        XCTAssertEqual(record.payload.url, "https://example.com/login")
        XCTAssertEqual(record.payload.passkey, PasskeyTests.fixtureCredential())
        // …and nothing is reported dropped for the well-formed credential.
        XCTAssertNil(
            content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.passkeyAttributes],
            "well-formed passkey attributes are consumed, not dropped; got \(content.summary.skippedCounts)")
    }

    // MARK: - Malformed input (typed failures)

    func testEmptyRootNameThrowsUnsupportedKdbx() {
        var document = KdbxDocument()
        document.root = KdbxGroup(name: "")
        XCTAssertThrowsError(try KdbxVaultMapper.nativeVault(from: document)) { error in
            XCTAssertEqual(error as? InteropError, .unsupportedKdbx)
        }
    }

    func testEmptyGroupNameThrowsEmptyName() {
        var document = KdbxDocument()
        document.root.groups.append(KdbxGroup(name: "  "))
        XCTAssertThrowsError(try KdbxVaultMapper.nativeVault(from: document)) { error in
            XCTAssertEqual(error as? InteropError, .emptyName)
        }
    }

    func testOversizedAttachmentThrowsAttachmentTooLarge() throws {
        var document = KdbxDocument()
        var entry = KdbxEntry()
        entry.setValue("Title", "Huge")
        document.binaries.append(KdbxInnerHeader.Binary(
            flags: 0x01, content: Data(count: KdbxAttachments.sizeLimitBytes + 1)))
        entry.binaries.append(KdbxBinaryReference(key: "huge.bin", ref: 0))
        document.root.entries.append(entry)

        XCTAssertThrowsError(try KdbxVaultMapper.nativeVault(from: document)) { error in
            XCTAssertEqual(error as? InteropError, .attachmentTooLarge)
        }
    }

    func testEmptyTitleEntryIsCountedNotThrown() throws {
        var document = KdbxDocument()
        var unnamed = KdbxEntry()
        unnamed.setValue("UserName", "nobody")
        document.root.entries.append(unnamed)
        var named = KdbxEntry()
        named.setValue("Title", "Named")
        document.root.entries.append(named)

        let content = try KdbxVaultMapper.nativeVault(from: document)
        XCTAssertEqual(content.records.count, 1, "only the titled entry imports")
        XCTAssertEqual(content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.emptyName], 1)
    }

    func testTOTPAttributesMapToStoredSecret() throws {
        var document = KdbxDocument()
        var timeOtp = KdbxEntry()
        timeOtp.setValue("Title", "TimeOtp entry")
        timeOtp.setValue("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP")
        document.root.entries.append(timeOtp)

        var otpauth = KdbxEntry()
        otpauth.setValue("Title", "otpauth entry")
        otpauth.setValue("otp", "otpauth://totp/Eg?secret=ABC234DEF&issuer=Me")
        document.root.entries.append(otpauth)

        var plain = KdbxEntry()
        plain.setValue("Title", "plain entry")
        plain.setValue("otp", "not-a-uri")
        document.root.entries.append(plain)

        let content = try KdbxVaultMapper.nativeVault(from: document)
        XCTAssertEqual(content.records.first { $0.payload.title == "TimeOtp entry" }?.payload.totpSecret,
                       "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(content.records.first { $0.payload.title == "otpauth entry" }?.payload.totpSecret,
                       "ABC234DEF")
        XCTAssertNil(content.records.first { $0.payload.title == "plain entry" }?.payload.totpSecret)
    }

    func testCustomFieldsAndAutoTypeAndIconsAreCounted() throws {
        var document = KdbxDocument()
        var entry = KdbxEntry()
        entry.setValue("Title", "Customized")
        entry.setValue("Deployment-Notes", "internal") // custom attribute
        var autoType = KdbxAutoType()
        autoType.defaultSequence = "{PASSWORD}{ENTER}" // explicit user config
        entry.autoType = autoType
        entry.customIconUUID = UUID()
        document.root.entries.append(entry)

        // KeePassXC's default AutoType shell (enabled, no sequences) is NOT
        // a loss — only explicit configuration counts.
        var shellOnly = KdbxEntry()
        shellOnly.setValue("Title", "Shell only")
        shellOnly.autoType = KdbxAutoType()
        document.root.entries.append(shellOnly)

        let content = try KdbxVaultMapper.nativeVault(from: document)
        XCTAssertEqual(content.summary.recordCount, 2)
        XCTAssertEqual(content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.customFields], 1)
        XCTAssertEqual(content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.autotype], 1)
        XCTAssertEqual(content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.customIcons], 1)
    }

    func testDisabledRecycleBinDeletionsAreReportedNotImported() throws {
        var document = KdbxDocument()
        document.meta.recycleBinEnabled = false
        var entry = KdbxEntry()
        entry.setValue("Title", "Survivor")
        document.root.entries.append(entry)
        document.deletedObjects.append(KdbxDeletedObject(uuid: UUID()))

        let content = try KdbxVaultMapper.nativeVault(from: document)
        XCTAssertEqual(content.summary.recordCount, 1)
        XCTAssertEqual(content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.deletedObjects], 1)
    }

    func testSiblingNameCollisionIsUniquedAndCounted() throws {
        var document = KdbxDocument()
        // Three same-named SIBLING groups at the root level.
        document.root.groups.append(KdbxGroup(name: "Work"))
        document.root.groups.append(KdbxGroup(name: "Work"))
        document.root.groups.append(KdbxGroup(name: "Work"))

        let content = try KdbxVaultMapper.nativeVault(from: document)
        XCTAssertEqual(content.folders.map(\.name), ["Work", "Work 2", "Work 3"])
        XCTAssertEqual(content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.renamedFolders], 2)
        for folder in content.folders {
            XCTAssertNil(folder.parentID)
        }
    }

    // MARK: - Export: exclusion predicate (05-CONTEXT D-05)

    /// Table-driven three-state predicate: excluded iff `.custom` level OR
    /// `.seedPhrase` type — every (level, type) combination pinned.
    func testExclusionPredicateTable() {
        let excludedCombinations: [(RecordType, SecurityLevel)] = [
            (.password, .custom), (.totp, .custom), (.card, .custom),
            (.secureNote, .custom), (.seedPhrase, .custom),
            (.seedPhrase, .auto),
        ]
        let includedCombinations: [(RecordType, SecurityLevel)] = [
            (.password, .auto), (.totp, .auto), (.card, .auto),
            (.secureNote, .auto),
        ]
        for (type, level) in excludedCombinations {
            let record = Self.makeRecord(type: type, level: level)
            XCTAssertTrue(KdbxVaultMapper.isDefaultExcluded(record), "\(type)/\(level) must be excluded by default")
        }
        for (type, level) in includedCombinations {
            let record = Self.makeRecord(type: type, level: level)
            XCTAssertFalse(KdbxVaultMapper.isDefaultExcluded(record), "\(type)/\(level) must be included by default")
        }
    }

    private static func makeRecord(type: RecordType, level: SecurityLevel) -> DecryptedRecord {
        DecryptedRecord(
            id: UUID(), createdAt: Date(), type: type, level: level,
            payload: RecordPayload(title: "Row"), isArchived: false)
    }

    // MARK: - Export: mapper → KdbxWriter → KdbxReader readback

    /// Full export cycle over a rich native vault: folder tree, versioned
    /// record, attachment record, archived record — plus the excluded-by-
    /// default rows that must NOT appear — written with argon2idDefaults and
    /// read back (D-05/D-06).
    func testExportReadsBackWithHistoryAttachmentsAndGroups() throws {
        let vault = try VaultService.create(passphrase: fixturePassword)
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let t1 = t0.addingTimeInterval(60)

        let work = try vault.addFolder(name: "Work")
        let finance = try vault.addFolder(name: "Finance", parentID: work)

        let versionedID = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "Versioned", username: "v1-user", password: "v1-pass"),
            tags: ["dev"], folderID: work, at: t0)
        try vault.update(
            id: versionedID, type: .password, level: .auto,
            payload: RecordPayload(title: "Versioned", username: "v2-user", password: "v2-pass"),
            tags: ["dev", "web"], folderID: work, at: t1)

        let attachment = RecordAttachment(
            id: UUID(), name: "kit.bin", contentType: nil, data: Data([1, 2, 3, 4, 5]))
        let attachmentID = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "Carrier", password: "carrier-pass"),
            attachments: [attachment], at: t0)

        let seedID = try vault.add(
            .seedPhrase, level: .auto,
            payload: RecordPayload(title: "Cold Seed", seedPhrase: ["abandon", "ability"]), at: t0)
        let l2ID = try vault.add(
            .secureNote, level: .custom, payload: RecordPayload(title: "L2 note"), at: t0)

        let archivedID = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "Archived Row", password: "old-pass"), at: t0)
        try vault.archive(id: archivedID)

        let records = try vault.records()
        let versions = try vault.allVersions()
        // allVersions() excludes the newest per id (it rides records()).
        XCTAssertEqual(versions[versionedID]?.count, 1, "one prior version")
        XCTAssertEqual(versions[attachmentID] ?? [], [])

        let included = Set(records.filter { !KdbxVaultMapper.isDefaultExcluded($0) }.map(\.id))
        XCTAssertEqual(included.count, 3, "seed + L2 excluded: versioned, carrier, archived remain")

        let input = KdbxVaultMapper.ExportInput(
            records: records, versions: versions, folders: vault.folders(), includedIDs: included)
        let (document, binaries) = try KdbxVaultMapper.kdbxDocument(from: input)
        XCTAssertEqual(binaries.count, 1, "attachment pooled once")
        XCTAssertEqual(document.meta.recycleBinEnabled, true, "D-05: normal KeePassXC-compatible meta")
        XCTAssertTrue(document.root.allEntries().count == 3)

        let data = try KdbxWriter.write(
            document, credentials: .init(password: "export-pass-1"),
            binaries: binaries, options: .argon2idDefaults())

        // Wrong passphrase fails closed with the typed credential error.
        XCTAssertThrowsError(try KdbxReader.read(data, credentials: .init(password: "wrong-pass"))) { error in
            XCTAssertEqual(error as? KdbxError, .wrongCredentials)
        }

        let back = try KdbxReader.read(data, credentials: .init(password: "export-pass-1"))

        // Group tree round-trips (parent → child).
        XCTAssertEqual(back.root.groups.count, 1)
        let workGroup = try XCTUnwrap(back.root.groups.first)
        XCTAssertEqual(workGroup.name, "Work")
        XCTAssertEqual(workGroup.groups.map(\.name), ["Finance"])

        // Versioned record: current values + history depth + prior values.
        let backVersioned = try XCTUnwrap(workGroup.entries.first { $0.name == "Versioned" })
        XCTAssertEqual(backVersioned.username, "v2-user")
        XCTAssertEqual(backVersioned.password, "v2-pass")
        XCTAssertEqual(backVersioned.tags, "dev web")
        XCTAssertEqual(backVersioned.historyCount, 1)
        XCTAssertEqual(backVersioned.history[0].username, "v1-user")
        XCTAssertEqual(backVersioned.history[0].password, "v1-pass")
        XCTAssertLessThan(
            backVersioned.history[0].times?.lastModificationTime ?? .distantPast,
            backVersioned.times?.lastModificationTime ?? .distantFuture,
            "history must be older than the current version")

        // Attachment bytes survive the pool indirection.
        let backCarrier = try XCTUnwrap(back.root.allEntries().first { $0.name == "Carrier" })
        XCTAssertEqual(backCarrier.attachments.count, 1)
        XCTAssertEqual(back.binaries[backCarrier.attachments[0].ref].content, Data([1, 2, 3, 4, 5]))

        // Archived exports as an ORDINARY entry (D-05)…
        let backArchived = try XCTUnwrap(back.root.allEntries().first { $0.name == "Archived Row" })
        XCTAssertEqual(backArchived.password, "old-pass")
        // …and the excluded rows are absent.
        let names = back.root.allEntries().map(\.name)
        XCTAssertFalse(names.contains("Cold Seed"))
        XCTAssertFalse(names.contains("L2 note"))
    }

    /// WR-04 regression: versions of one id sharing a timestamp must resolve
    /// with ONE canonical rule — last-appended wins (the `>=` rule in
    /// `records()`) — and `allVersions()` must exclude exactly that entry.
    /// Divergent tie-breaks would make export duplicate the current version
    /// into history while silently losing another version.
    func testEqualTimestampTieBreakAgreesBetweenRecordsAndAllVersions() throws {
        let vault = try VaultService.create(passphrase: fixturePassword)
        let tied = Date(timeIntervalSince1970: 1_700_000_500)
        let id = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "Tied", password: "v1"), at: tied)
        try vault.update(
            id: id, type: .password, level: .auto,
            payload: RecordPayload(title: "Tied", password: "v2"), at: tied)
        try vault.update(
            id: id, type: .password, level: .auto,
            payload: RecordPayload(title: "Tied", password: "v3"), at: tied)

        // records(): last-appended wins on equal timestamps.
        let current = try vault.records()
        XCTAssertEqual(current.count, 1)
        XCTAssertEqual(current[0].payload.password, "v3")

        // allVersions(): the excluded "newest" is exactly the last-appended
        // entry records() keeps; history is the earlier versions once each,
        // in append order.
        let history = try vault.allVersions()[id] ?? []
        XCTAssertEqual(history.map(\.payload.password), ["v1", "v2"])
        XCTAssertFalse(history.contains(where: { $0.payload.password == "v3" }),
                       "the current version must never leak into history")

        // Export integrity invariant: history + current covers every version
        // exactly once — nothing duplicated, nothing lost.
        let all = history.map(\.payload.password) + [current[0].payload.password]
        XCTAssertEqual(all.count, 3)
        XCTAssertEqual(Set(all), ["v1", "v2", "v3"])
    }

    /// An export folder whose parent reference never resolves fails typed.
    func testOrphanFolderThrowsMappingFailed() throws {
        let input = KdbxVaultMapper.ExportInput(
            records: [],
            versions: [:],
            folders: [Folder(name: "Orphan", parentID: UUID())],
            includedIDs: [])
        XCTAssertThrowsError(try KdbxVaultMapper.kdbxDocument(from: input)) { error in
            XCTAssertEqual(error as? InteropError, .mappingFailed)
        }
    }

    /// A record referencing an unknown folder id fails typed (no silent
    /// re-parenting on the export path).
    func testRecordWithUnknownFolderIDThrowsMappingFailed() throws {
        let record = DecryptedRecord(
            id: UUID(), createdAt: Date(), type: .password, level: .auto,
            payload: RecordPayload(title: "Lost"), folderID: UUID(), isArchived: false)
        let input = KdbxVaultMapper.ExportInput(
            records: [record], versions: [:], folders: [], includedIDs: [record.id])
        XCTAssertThrowsError(try KdbxVaultMapper.kdbxDocument(from: input)) { error in
            XCTAssertEqual(error as? InteropError, .mappingFailed)
        }
    }

    // MARK: - Export: kxc corpus round trip (import → export → read back)

    /// kxc-default → nativeVault → kdbxDocument → KdbxWriter → KdbxReader:
    /// record-level fields align with the original KeePassXC library inside
    /// the mapped surface (成功标准 2 round-trip half).
    func testKxcDefaultImportExportRoundtrip() throws {
        let original = try openCorpus("kxc-default.kdbx")
        let content = try KdbxVaultMapper.nativeVault(from: original)

        let records = content.records.map { mapped in
            DecryptedRecord(
                id: UUID(), createdAt: Date(), type: mapped.type, level: mapped.level,
                payload: mapped.payload, tags: mapped.tags, folderID: mapped.folderID,
                attachments: mapped.attachments, isArchived: mapped.isArchived)
        }
        let input = KdbxVaultMapper.ExportInput(
            records: records,
            versions: [:],
            folders: content.folders,
            includedIDs: Set(records.map(\.id)))
        let (document, binaries) = try KdbxVaultMapper.kdbxDocument(from: input)
        let data = try KdbxWriter.write(
            document, credentials: .init(password: corpusPassword),
            binaries: binaries, options: .argon2idDefaults())
        let back = try KdbxReader.read(data, credentials: .init(password: corpusPassword))

        XCTAssertEqual(Set(back.root.allEntries().map { $0.name ?? "" }),
                       Set(original.root.allEntries().map { $0.name ?? "" }))
        for originalEntry in original.root.allEntries() {
            let backEntry = try XCTUnwrap(back.root.allEntries().first { $0.name == originalEntry.name })
            XCTAssertEqual(backEntry.username, originalEntry.username)
            XCTAssertEqual(backEntry.password, originalEntry.password)
            XCTAssertEqual(backEntry.url, originalEntry.url)
            XCTAssertEqual(backEntry.notes, originalEntry.notes)
        }
    }

    // MARK: - Canonical export fixture (dev-machine oracle input)

    /// One-time/dev regeneration of the canonical EXPORT fixture consumed by
    /// scripts/export-oracle.sh (keepassxc-cli must open it and list every
    /// entry). Uses the uniform corpus password so CorpusGateTests can read
    /// it. Not run in CI — the committed file is what CI consumes:
    ///   GENERATE_EXPORT_FIXTURE=1 swift test --filter InteropTests/testGenerateExportFixture
    func testGenerateExportFixture() throws {
        guard ProcessInfo.processInfo.environment["GENERATE_EXPORT_FIXTURE"] == "1" else {
            throw XCTSkip("Set GENERATE_EXPORT_FIXTURE=1 to (re)generate rv-export-roundtrip.kdbx")
        }

        let vault = try VaultService.create(passphrase: corpusPassword)
        let work = try vault.addFolder(name: "Work")
        _ = try vault.addFolder(name: "Finance", parentID: work)

        _ = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "GitHub", username: "alice", password: "pw-github-1",
                                   notes: "synthetic entry one", url: "https://example.com"),
            tags: ["dev", "web"], folderID: work)
        let rotating = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "Rotating Secret", username: "carol", password: "secret-v1"))
        try vault.update(
            id: rotating, type: .password, level: .auto,
            payload: RecordPayload(title: "Rotating Secret", username: "carol", password: "secret-v2"))
        let kit = RecordAttachment(
            id: UUID(), name: "backup-kit.txt", contentType: "text/plain",
            data: Data("ravenvault synthetic export attachment\n".utf8))
        _ = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "Carrier", password: "carrier-pass"),
            attachments: [kit])
        let archived = try vault.add(
            .password, level: .auto,
            payload: RecordPayload(title: "Archived Row", password: "old-pass"))
        try vault.archive(id: archived)

        let records = try vault.records()
        let included = Set(records.filter { !KdbxVaultMapper.isDefaultExcluded($0) }.map(\.id))
        let (document, binaries) = try KdbxVaultMapper.kdbxDocument(from: .init(
            records: records, versions: try vault.allVersions(),
            folders: vault.folders(), includedIDs: included))
        let data = try KdbxWriter.write(
            document, credentials: .init(password: corpusPassword),
            binaries: binaries, options: .argon2idDefaults())

        let dir = URL(fileURLWithPath: TestFixtures.packageRoot)
            .appendingPathComponent("Tests/Fixtures/Kdbx")
        try data.write(to: dir.appendingPathComponent("rv-export-roundtrip.kdbx"))
        // Self-check: our reader must accept it with the expected content.
        let back = try KdbxReader.read(data, credentials: .init(password: corpusPassword))
        XCTAssertEqual(back.root.allEntries().count, 4)
        print("rv-export-roundtrip.kdbx written:", TestFixtures.sha256Hex(data))
    }
}
