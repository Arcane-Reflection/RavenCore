import XCTest
@testable import RavenCore

/// Format-versioning migration: v1 PBKDF2 documents stay unlockable forever
/// (D-04), unlocked saves upgrade to Argon2id (D-01 defaults), locked saves
/// don't touch the format.
final class MigrationTests: XCTestCase {

    private let passphrase = "correct horse battery staple"

    func testV1FixtureUnlocksForever() throws {
        let data = try TestFixtures.loadV1Fixture("v1-with-records.json")

        let doc = try JSONDecoder().decode(VaultDocument.self, from: data)
        XCTAssertEqual(doc.header.formatVersion, 1)
        XCTAssertEqual(doc.header.kdfAlgorithm, VaultKDF.pbkdf2, "v1 header must infer PBKDF2")

        let vault = try VaultService.unlock(serializedDocument: data, passphrase: passphrase)
        let records = try vault.records()
        XCTAssertEqual(records.count, 3)
        XCTAssertEqual(records[0].payload.title, "GitHub")
        XCTAssertEqual(records[0].payload.password, "hunter2!")
        XCTAssertEqual(records[1].type, .seedPhrase)
        XCTAssertEqual(records[1].level, .custom)
        XCTAssertEqual(records[1].payload.seedPhrase?.count, 5)
        XCTAssertEqual(records.filter(\.isArchived).count, 1)
        XCTAssertTrue(vault.verifyChain())
    }

    func testV1MinimalFixtureUnlocks() throws {
        let data = try TestFixtures.loadV1Fixture("v1-minimal.json")
        let vault = try VaultService.unlock(serializedDocument: data, passphrase: passphrase)
        XCTAssertTrue(try vault.records().isEmpty)
        XCTAssertTrue(vault.verifyChain())
    }

    func testUnlockedSaveUpgradesToArgon2id() throws {
        let original = try TestFixtures.loadV1Fixture("v1-with-records.json")
        let before = try VaultService.unlock(serializedDocument: original, passphrase: passphrase)
        let recordsBefore = try before.records()

        // D-04: saving an unlocked legacy vault upgrades it in place.
        let upgraded = try before.serializedDocument()
        let doc = try JSONDecoder().decode(VaultDocument.self, from: upgraded)
        XCTAssertEqual(doc.header.formatVersion, 2)
        XCTAssertEqual(doc.header.kdfAlgorithm, VaultKDF.argon2id)
        XCTAssertEqual(doc.header.kdfMemoryKiB, KeyDerivation.argon2MemoryKiB)
        XCTAssertEqual(doc.header.kdfTimeCost, KeyDerivation.argon2TimeCost)
        XCTAssertEqual(doc.header.kdfParallelism, KeyDerivation.argon2Parallelism)
        XCTAssertNotEqual(doc.header.kdfSalt, try JSONDecoder().decode(VaultDocument.self, from: original).header.kdfSalt,
                          "upgrade must re-salt")

        // The upgraded vault re-unlocks with the same passphrase, records intact.
        let reopened = try VaultService.unlock(serializedDocument: upgraded, passphrase: passphrase)
        XCTAssertEqual(try reopened.records(), recordsBefore)
        XCTAssertTrue(reopened.verifyChain())
    }

    func testLockedSaveDoesNotUpgrade() throws {
        let original = try TestFixtures.loadV1Fixture("v1-minimal.json")
        let vault = try VaultService.unlock(serializedDocument: original, passphrase: passphrase)
        vault.lock()

        let data = try vault.serializedDocument()
        let doc = try JSONDecoder().decode(VaultDocument.self, from: data)
        XCTAssertEqual(doc.header.formatVersion, 1, "locked save must not upgrade")
        XCTAssertEqual(doc.header.kdfAlgorithm, VaultKDF.pbkdf2)
    }

    func testTamperedV1FixtureIsWrongPassphrase() throws {
        var doc = try JSONDecoder().decode(VaultDocument.self, from: TestFixtures.loadV1Fixture("v1-minimal.json"))
        // Flip a byte inside the wrapped data key ciphertext (GCM tag fails).
        doc.header.wrappedDataKey.ciphertext[doc.header.wrappedDataKey.ciphertext.count - 1] ^= 0xFF
        let data = try JSONEncoder().encode(doc)
        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: data, passphrase: passphrase)) { error in
            XCTAssertEqual(error as? VaultError, .wrongPassphrase)
        }
    }

    func testUnknownKDFAlgorithmRejected() throws {
        var doc = try JSONDecoder().decode(VaultDocument.self, from: TestFixtures.loadV1Fixture("v1-minimal.json"))
        doc.header.kdfAlgorithm = "rsa9000"
        let data = try JSONEncoder().encode(doc)
        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: data, passphrase: passphrase)) { error in
            XCTAssertEqual(error as? VaultError, .corruptDocument)
        }
    }

    func testExplicitRewrapRequiresUnlockedAndNonEmptyPassphrase() throws {
        let vault = try VaultService.createLegacyPBKDF2(passphrase: "legacy-pw", iterations: 10_000)
        vault.lock()
        XCTAssertThrowsError(try vault.rewrap(passphrase: "new-pw")) { XCTAssertEqual($0 as? VaultError, .locked) }

        let unlocked = try VaultService.createLegacyPBKDF2(passphrase: "legacy-pw", iterations: 10_000)
        XCTAssertThrowsError(try unlocked.rewrap(passphrase: "")) { XCTAssertEqual($0 as? VaultError, .wrongPassphrase) }

        try unlocked.rewrap(passphrase: "brand-new-pw")
        let data = try unlocked.serializedDocument()
        XCTAssertEqual(try JSONDecoder().decode(VaultDocument.self, from: data).header.formatVersion, 2)
        let reopened = try VaultService.unlock(serializedDocument: data, passphrase: "brand-new-pw")
        XCTAssertTrue(reopened.verifyChain())
        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: data, passphrase: "legacy-pw")) { error in
            XCTAssertEqual(error as? VaultError, .wrongPassphrase)
        }
    }

    func testNewVaultsAreV2WithPerVaultParameters() throws {
        let a = try VaultService.create(passphrase: "pw-one")
        let b = try VaultService.create(passphrase: "pw-two")
        let docA = try JSONDecoder().decode(VaultDocument.self, from: try a.serializedDocument())
        let docB = try JSONDecoder().decode(VaultDocument.self, from: try b.serializedDocument())

        for doc in [docA, docB] {
            XCTAssertEqual(doc.header.formatVersion, 2)
            XCTAssertEqual(doc.header.kdfAlgorithm, VaultKDF.argon2id)
            XCTAssertEqual(doc.header.kdfMemoryKiB, 65_536)
            XCTAssertEqual(doc.header.kdfTimeCost, 3)
            XCTAssertEqual(doc.header.kdfParallelism, 2)
        }
        // ROADMAP SC#1: KDF parameters are per-vault (fresh salt every create).
        XCTAssertNotEqual(docA.header.kdfSalt, docB.header.kdfSalt)
        XCTAssertNotEqual(docA.header.wrappedDataKey, docB.header.wrappedDataKey)
    }
}
