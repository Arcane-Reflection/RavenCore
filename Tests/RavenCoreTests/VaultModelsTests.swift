import XCTest
@testable import RavenCore

/// `RecordType.emergencyCard` decode/round-trip compatibility (07-CONTEXT
/// D-16/D-17, 07-04 Task 1): the additive enum case follows the passkey
/// precedent — old envelopes decode unchanged, a card envelope round-trips
/// with its type preserved, and `formatVersion` is NOT bumped. The app-layer
/// `EmergencyCardPolicy` predicate (asserted in the app test target) is the
/// single classification function; the engine only carries the type and the
/// defense-in-depth `isDefaultExcluded` clause.
final class VaultModelsTests: XCTestCase {

    // MARK: - Decode compatibility (pre-card envelopes decode forever)

    /// A hand-written pre-card envelope (exactly the bytes a Phase 4–6 writer
    /// produced — no card raw value was ever written) decodes unchanged.
    func testPreCardEnvelopeJSONDecodes() throws {
        let legacyJSON = """
        {
          "type": "password",
          "level": "auto",
          "record": {
            "title": "Legacy",
            "username": "alice",
            "password": "pw",
            "notes": "",
            "url": "https://example.com"
          },
          "tags": ["Old"],
          "folderID": null
        }
        """
        let envelope = try JSONDecoder().decode(RecordEnvelope.self, from: Data(legacyJSON.utf8))
        XCTAssertEqual(envelope.type, .password)
        XCTAssertEqual(envelope.record.title, "Legacy")
        XCTAssertNil(envelope.record.seedPhrase)
        XCTAssertNil(envelope.record.passkey)
    }

    /// The full sealed path: a vault containing an Emergency Card record
    /// survives serialize → unlock with the type preserved end-to-end.
    func testSealedVaultCarriesEmergencyCardAcrossSerializeUnlock() throws {
        let vault = try VaultService.create(passphrase: "test-passphrase")
        _ = try vault.add(
            .emergencyCard,
            level: .auto,
            payload: RecordPayload(
                title: "If you find me",
                notes: "Call Dr. Otter at 555-0100. No crypto here."))
        let data = try vault.serializedDocument()

        let reopened = try VaultService.unlock(
            serializedDocument: data, passphrase: "test-passphrase")
        let record = try XCTUnwrap(reopened.records().first)
        XCTAssertEqual(record.type, .emergencyCard)
        XCTAssertEqual(record.payload.title, "If you find me")
    }

    /// Envelope-level JSON round trip: `"emergencyCard"` encodes and decodes
    /// back as the same raw value (frozen wire format, additive-safe).
    func testEmergencyCardRawValueRoundTrips() throws {
        XCTAssertEqual(RecordType.emergencyCard.rawValue, "emergencyCard")
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let data = try encoder.encode(RecordType.emergencyCard)
        let decoded = try decoder.decode(RecordType.self, from: data)
        XCTAssertEqual(decoded, .emergencyCard)
    }

    /// `formatVersion` is NOT bumped by the additive case (the passkey
    /// precedent): newly created documents still write format version 2.
    func testFormatVersionUnchanged() throws {
        let vault = try VaultService.create(passphrase: "test-passphrase")
        let document = try JSONDecoder().decode(VaultDocument.self, from: vault.serializedDocument())
        XCTAssertEqual(document.header.formatVersion, 2, "additive enum case must not bump formatVersion")
    }

    // MARK: - Export defense in depth (the hard filter lives app-side)

    func testEmergencyCardIsDefaultExcluded() {
        let card = DecryptedRecord(
            id: UUID(), createdAt: Date(), type: .emergencyCard, level: .auto,
            payload: RecordPayload(title: "Card"),
            isArchived: false)
        XCTAssertTrue(KdbxVaultMapper.isDefaultExcluded(card))
        // The pre-existing defaults keep their behavior.
        let seed = DecryptedRecord(
            id: UUID(), createdAt: Date(), type: .seedPhrase, level: .auto,
            payload: RecordPayload(title: "Seed"),
            isArchived: false)
        XCTAssertTrue(KdbxVaultMapper.isDefaultExcluded(seed))
        let ordinary = DecryptedRecord(
            id: UUID(), createdAt: Date(), type: .password, level: .auto,
            payload: RecordPayload(title: "Pw"),
            isArchived: false)
        XCTAssertFalse(KdbxVaultMapper.isDefaultExcluded(ordinary))
    }
}
