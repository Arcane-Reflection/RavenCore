import XCTest
@testable import RavenCore

/// `RecordPayload.passkey` native storage (06-CONTEXT D-09, fixture-first
/// discipline): the canonical fixture `Tests/Fixtures/record-passkey-fixture.json`
/// was committed BEFORE the format code landed, and every assertion here is
/// measured against it. The fixture's credential values are derived verbatim
/// from the kxc-passkey.kdbx corpus oracle (`PasskeyTests.fixtureCredential`)
/// so the native envelope and the KPEX oracle agree.
///
/// Compatibility contract: a pre-passkey envelope decodes forever with
/// `passkey == nil` (synthesized optional decoding tolerates absence), the
/// populated fixture round-trips byte-stably, and re-encoding an envelope
/// without a passkey omits the key — `formatVersion` is unchanged (the
/// attachments precedent, VaultModels.swift additive-optional rule).
final class RecordPayloadPasskeyTests: XCTestCase {

    // MARK: - Fixture access

    private static let fixtureData: Data = {
        let url = URL(fileURLWithPath: TestFixtures.packageRoot)
            .appendingPathComponent("Tests/Fixtures/record-passkey-fixture.json")
        precondition(FileManager.default.fileExists(atPath: url.path),
                     "Missing canonical passkey fixture — it must precede the format code (D-09 fixture-first)")
        return try! Data(contentsOf: url)
    }()

    private func decodeEnvelope(_ data: Data) throws -> RecordEnvelope {
        try JSONDecoder().decode(RecordEnvelope.self, from: data)
    }

    /// The pre-passkey document: the canonical fixture with the `passkey`
    /// key removed — exactly the bytes an extension-era writer produced.
    private var prePasskeyData: Data {
        get throws {
            var object = try JSONSerialization.jsonObject(
                with: Self.fixtureData) as! [String: Any]
            var record = object["record"] as! [String: Any]
            record.removeValue(forKey: "passkey")
            object["record"] = record
            return try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys])
        }
    }

    // MARK: - Decode compatibility (pre-passkey envelopes decode forever)

    func testPrePasskeyEnvelopeDecodesWithNilPasskey() throws {
        let envelope = try decodeEnvelope(try prePasskeyData)
        XCTAssertNil(envelope.record.passkey, "absent key must decode to nil")
        XCTAssertEqual(envelope.type, .password)
        XCTAssertEqual(envelope.level, .auto)
        XCTAssertEqual(envelope.record.title, "RavenTest (Passkey)")
        XCTAssertEqual(envelope.record.username, "alice@example.com")
        XCTAssertEqual(envelope.record.url, "https://example.com/login")
        XCTAssertEqual(envelope.tags, ["Passkey"])
    }

    /// The sealed native path end-to-end: a passkey payload survives the
    /// real document serialize → unlock cycle (decode-compat at the vault
    /// level, not just the envelope).
    func testSealedVaultCarriesPasskeyAcrossSerializeUnlock() throws {
        var payload = RecordPayload(
            title: "Native passkey", username: "alice@example.com",
            url: "https://example.com/login")
        payload.passkey = PasskeyTests.fixtureCredential()

        let vault = try VaultService.create(passphrase: "test-passphrase")
        _ = try vault.add(.password, level: .auto, payload: payload)
        let data = try vault.serializedDocument()

        let reopened = try VaultService.unlock(serializedDocument: data, passphrase: "test-passphrase")
        let record = try XCTUnwrap(reopened.records().first)
        XCTAssertEqual(record.payload.passkey, PasskeyTests.fixtureCredential())

        // A record created WITHOUT a passkey keeps decoding beside one that
        // carries it (mixed old/new documents are the compatibility target).
        let legacyData = try TestFixtures.loadV1Fixture("v2-baseline.json")
        let legacy = try VaultService.unlock(
            serializedDocument: legacyData, passphrase: "correct horse battery staple")
        for record in try legacy.records() {
            XCTAssertNil(record.payload.passkey)
        }
    }

    // MARK: - Populated fixture round trip (byte-stable)

    func testPopulatedFixtureDecodesToKpeXOracleCredential() throws {
        let envelope = try decodeEnvelope(Self.fixtureData)
        XCTAssertEqual(envelope.record.passkey, PasskeyTests.fixtureCredential(),
                       "fixture values must equal the kxc corpus oracle credential")
    }

    /// Foundation's JSONEncoder scrambles key order across calls unless
    /// `.sortedKeys` is set — the stable-encoding oracle needs determinism.
    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    func testPopulatedFixtureRoundTripsByteStably() throws {
        let first = try decodeEnvelope(Self.fixtureData)
        let encodedOnce = try Self.encoder.encode(first)
        let second = try decodeEnvelope(encodedOnce)
        let encodedTwice = try Self.encoder.encode(second)

        XCTAssertEqual(first, second, "decode → encode → decode must be value-stable")
        XCTAssertEqual(encodedOnce, encodedTwice, "re-encoding must be byte-stable")

        // The populated fixture keeps the passkey on the wire.
        let object = try JSONSerialization.jsonObject(with: encodedOnce) as! [String: Any]
        let record = object["record"] as! [String: Any]
        XCTAssertTrue(record.keys.contains("passkey"), "populated passkey must encode")
    }

    // MARK: - Omit when nil (wire format stability)

    func testEncodeOmitsPasskeyWhenNil() throws {
        let envelope = try decodeEnvelope(try prePasskeyData)
        let encoded = try Self.encoder.encode(envelope)
        let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        let record = object["record"] as! [String: Any]
        XCTAssertFalse(record.keys.contains("passkey"),
                       "a nil passkey must be omitted, not written as null")
    }

    func testPayloadInitDefaultsToNilPasskey() {
        let payload = RecordPayload(title: "Plain")
        XCTAssertNil(payload.passkey)
    }

    // MARK: - kdbx corpus gate: import with passkey intact, export canonical

    private func openCorpus(_ name: String) throws -> KdbxDocument {
        let url = URL(fileURLWithPath: TestFixtures.packageRoot)
            .appendingPathComponent("Tests/Fixtures/Kdbx")
            .appendingPathComponent(name)
        let data = try Data(contentsOf: url)
        return try KdbxReader.read(
            data, credentials: KdbxReader.Credentials(password: "correct-horse-battery"))
    }

    /// The SC3 anchor's engine half: the kxc-passkey.kdbx corpus entry
    /// imports into a native record with its passkey intact and no skip
    /// inflation — the Phase 5 known gap is closed on import.
    func testKxcCorpusImportYieldsPasskeyBearingRecord() throws {
        let content = try KdbxVaultMapper.nativeVault(from: try openCorpus("kxc-passkey.kdbx"))

        XCTAssertEqual(content.summary.recordCount, 1)
        let record = try XCTUnwrap(content.records.first)
        XCTAssertEqual(record.payload.passkey, PasskeyTests.fixtureCredential(),
                       "kxc corpus passkey must land in payload.passkey verbatim")
        XCTAssertNil(
            content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.passkeyAttributes],
            "a well-formed passkey entry must not be skip-counted; got \(content.summary.skippedCounts)")
    }

    /// A malformed passkey entry imports without the credential and counts
    /// exactly once under `passkeyAttributes` (honest accounting).
    func testMalformedPasskeyEntryCountsUnderPasskeyAttributes() throws {
        var document = KdbxDocument()
        var entry = KdbxEntry()
        entry.setValue("Title", "Broken passkey")
        entry.setValue(KdbxPasskey.usernameKey, "alice@example.com")
        // credentialID present but userHandle missing → read throws.
        entry.setValue(KdbxPasskey.credentialIDKey, "cred", protected: true)
        entry.setValue(KdbxPasskey.privateKeyPEMKey, PasskeyTests.fixturePEM, protected: true)
        entry.setValue(KdbxPasskey.relyingPartyKey, "example.com")
        document.root.entries.append(entry)

        let content = try KdbxVaultMapper.nativeVault(from: document)
        XCTAssertEqual(content.summary.recordCount, 1, "the entry itself still imports")
        let record = try XCTUnwrap(content.records.first)
        XCTAssertNil(record.payload.passkey)
        XCTAssertEqual(
            content.summary.skippedCounts[KdbxVaultMapper.ImportSummary.SkipKey.passkeyAttributes],
            1, "exactly the malformed passkey entry is counted")
    }

    /// The SC3 anchor's export half: re-exporting the imported corpus record
    /// produces an entry KeePassXC-equivalent on the KPEX_PASSKEY_* attribute
    /// set — same keys, values, and protection layout as the canonical
    /// `KdbxPasskey.write` output (the same oracle assertions the Phase 2
    /// suite uses; corpus fixtures untouched).
    func testExportRewritesCanonicalKpeXAttributeSet() throws {
        let content = try KdbxVaultMapper.nativeVault(from: try openCorpus("kxc-passkey.kdbx"))
        let mapped = try XCTUnwrap(content.records.first)

        let record = DecryptedRecord(
            id: UUID(),
            createdAt: mapped.currentAt,
            type: mapped.type,
            level: mapped.level,
            payload: mapped.payload,
            tags: mapped.tags,
            folderID: mapped.folderID,
            attachments: mapped.attachments,
            isArchived: mapped.isArchived)
        let input = KdbxVaultMapper.ExportInput(
            records: [record],
            versions: [:],
            folders: content.folders,
            includedIDs: [record.id])
        let (document, binaries) = try KdbxVaultMapper.kdbxDocument(from: input)

        let credentials = try KdbxReader.Credentials(password: "correct-horse-battery")
        let data = try KdbxWriter.write(document, credentials: credentials, binaries: binaries)
        let reopened = try KdbxReader.read(data, credentials: credentials)

        let exported = try XCTUnwrap(reopened.root.allEntries().first as KdbxEntry?)
        let reread = try XCTUnwrap(try KdbxPasskey.read(from: exported))
        XCTAssertEqual(reread, PasskeyTests.fixtureCredential(),
                       "export → file → import must preserve the credential verbatim")

        // Attribute-set equivalence against the canonical writer: for every
        // KPEX attribute the freshly-written oracle entry carries, the
        // exported entry carries the same key, value, and protection flag.
        var oracle = KdbxEntry()
        try KdbxPasskey.write(
            PasskeyTests.fixtureCredential(), into: &oracle,
            title: mapped.payload.title, originURL: mapped.payload.url)
        let kpeKeys = oracle.strings.map(\.key).filter { $0.hasPrefix("KPEX_PASSKEY") }
        XCTAssertEqual(kpeKeys.count, 7, "oracle canonical set has seven attributes")
        func attribute(_ entry: KdbxEntry, _ key: String) -> KdbxString? {
            entry.strings.first { $0.key == key }
        }
        for key in kpeKeys {
            let oracleAttr = try XCTUnwrap(attribute(oracle, key))
            let exportedAttr = try XCTUnwrap(attribute(exported, key), key)
            XCTAssertEqual(exportedAttr, oracleAttr,
                           "\(key) must be byte-equivalent (value + protection)")
        }

        // The KeePassXC shell conventions survive the export too.
        XCTAssertEqual(exported.iconId, 13)
        XCTAssertEqual(exported.tags?.contains("Passkey"), true)
    }

    /// A passkey record exports with its history versions carrying the
    /// canonical attribute set per version (D-09: current AND history).
    func testExportWritesPasskeyIntoHistoryVersions() throws {
        var current = RecordPayload(
            title: "Rotated passkey", username: "alice@example.com",
            url: "https://example.com/login")
        current.passkey = PasskeyTests.fixtureCredential()
        var older = current
        older.passkey?.username = "older@example.com"
        let record = DecryptedRecord(
            id: UUID(), createdAt: Date(timeIntervalSince1970: 100),
            type: .password, level: .auto, payload: current,
            tags: nil, folderID: nil, attachments: nil, isArchived: false)
        let version = RecordVersion(
            payload: older, tags: nil, folderID: nil, attachments: nil,
            at: Date(timeIntervalSince1970: 50))

        let input = KdbxVaultMapper.ExportInput(
            records: [record], versions: [record.id: [version]], folders: [],
            includedIDs: [record.id])
        let (document, binaries) = try KdbxVaultMapper.kdbxDocument(from: input)
        let credentials = try KdbxReader.Credentials(password: "correct-horse-battery")
        let data = try KdbxWriter.write(document, credentials: credentials, binaries: binaries)
        let reopened = try KdbxReader.read(data, credentials: credentials)

        let entry = try XCTUnwrap(reopened.root.allEntries().first as KdbxEntry?)
        XCTAssertEqual(try KdbxPasskey.read(from: entry)?.username, "alice@example.com")
        let historic = try XCTUnwrap(entry.history.last)
        XCTAssertTrue(KdbxPasskey.isPasskey(historic))
        XCTAssertEqual(try KdbxPasskey.read(from: historic)?.username, "older@example.com")
    }
}
