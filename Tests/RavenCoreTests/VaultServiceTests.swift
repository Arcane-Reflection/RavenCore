import CryptoKit
import XCTest
@testable import RavenCore

final class VaultServiceTests: XCTestCase {

    private let passphrase = "correct horse battery staple"

    private func makeRecord(title: String) -> RecordPayload {
        RecordPayload(title: title, username: "u@example.com", password: "hunter2!", notes: "")
    }

    func testCreateAddSaveUnlockRoundTrip() throws {
        var vault = try VaultService.create(passphrase: passphrase)
        let id1 = try vault.add(.password, level: .auto, payload: makeRecord(title: "GitHub"))
        let id2 = try vault.add(.seedPhrase, level: .custom, payload: RecordPayload(title: "BTC", seedPhrase: ["abandon", "ability", "able"]))

        let data = try vault.serializedDocument()
        vault.lock()
        XCTAssertFalse(vault.isUnlocked)

        let reopened = try VaultService.unlock(serializedDocument: data, passphrase: passphrase)
        let records = try reopened.activeRecords()
        XCTAssertEqual(records.map(\.id), [id1, id2])
        XCTAssertEqual(records[0].payload.title, "GitHub")
        XCTAssertEqual(records[0].level, .auto)
        XCTAssertEqual(records[1].type, .seedPhrase)
        XCTAssertEqual(records[1].payload.seedPhrase, ["abandon", "ability", "able"])
        XCTAssertTrue(reopened.verifyChain())
    }

    func testWrongPassphraseThrows() throws {
        let vault = try VaultService.create(passphrase: passphrase)
        let data = try vault.serializedDocument()
        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: data, passphrase: "wrong")) { error in
            XCTAssertEqual(error as? VaultError, .wrongPassphrase)
        }
    }

    func testLockedOperationsThrow() throws {
        let vault = try VaultService.create(passphrase: passphrase)
        vault.lock()
        XCTAssertThrowsError(try vault.records()) { error in
            XCTAssertEqual(error as? VaultError, .locked)
        }
        XCTAssertThrowsError(try vault.add(.password, level: .auto, payload: makeRecord(title: "x")))
    }

    func testArchiveAndCompactPersist() throws {
        let vault = try VaultService.create(passphrase: passphrase)
        let keep = try vault.add(.password, level: .auto, payload: makeRecord(title: "Keep"))
        let drop = try vault.add(.password, level: .auto, payload: makeRecord(title: "Drop"))

        try vault.archive(id: drop)
        XCTAssertEqual(try vault.activeRecords().map(\.id), [keep])
        XCTAssertTrue(vault.verifyChain()) // archive keeps the chain intact

        XCTAssertEqual(try vault.compact(), 1)
        XCTAssertTrue(vault.verifyChain())

        let data = try vault.serializedDocument()
        let reopened = try VaultService.unlock(serializedDocument: data, passphrase: passphrase)
        XCTAssertEqual(try reopened.records().count, 1)
        XCTAssertEqual(try reopened.activeRecords().first?.payload.title, "Keep")
    }

    func testHeaderHeadHashTracksLog() throws {
        let vault = try VaultService.create(passphrase: passphrase)
        try vault.add(.password, level: .auto, payload: makeRecord(title: "One"))
        XCTAssertTrue(vault.verifyChain())
        XCTAssertNotEqual(vault.headHash, AppendOnlyLog.genesisHash)
    }

    func testCorruptDocumentRejected() {
        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: Data("not a vault".utf8), passphrase: passphrase)) { error in
            XCTAssertEqual(error as? VaultError, .corruptDocument)
        }
    }

    /// FW-03: a tampered/older document whose header carries out-of-bounds
    /// KDF parameters must surface as the module's `VaultError.corruptDocument`
    /// — a foreign `KeyDerivationError` never escapes `unlock`.
    func testTamperedHeaderKdfParametersSurfaceAsCorruptDocument() throws {
        // Version-1 document whose kdfIterations was zeroed (e.g. by tampering
        // or an ancient broken writer): the frozen pbkdf2SHA256 guard rejects
        // it; deriveKEK maps that to the module error before it escapes.
        var document = VaultDocument(
            header: VaultHeader(
                formatVersion: 1,
                kdfSalt: SecureRandom.bytes(count: 16),
                kdfIterations: 0,
                wrappedDataKey: SealedPayload(nonce: Data(repeating: 0, count: 12), ciphertext: Data(repeating: 0, count: 40)),
                deviceWrappedDataKey: nil,
                headHash: Data(),
                kdfAlgorithm: VaultKDF.pbkdf2
            ),
            log: AppendOnlyLog()
        )
        document.header.headHash = document.log.headHash
        let serialized = try JSONEncoder().encode(document)

        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: serialized, passphrase: "any")) { error in
            XCTAssertEqual(error as? VaultError, .corruptDocument)
        }
    }

    /// Rewrites a v2 vault's header fields to simulate tampering.
    private func tamperedV2(passphrase: String, _ mutate: (inout VaultHeader) -> Void) throws -> Data {
        let vault = try VaultService.create(passphrase: passphrase)
        var document = try JSONDecoder().decode(VaultDocument.self, from: vault.serializedDocument())
        mutate(&document.header)
        return try JSONEncoder().encode(document)
    }

    /// FI-08: a tampered header cannot steer unlock into a jetsam-scale
    /// (4 GiB) Argon2 allocation — the policy ceiling rejects it typed and
    /// fast. The wall-clock assert documents the resource bound.
    func testTamperedHeaderMemoryCeilingRejected() throws {
        let serialized = try tamperedV2(passphrase: passphrase) {
            $0.kdfMemoryKiB = 4_194_304 // 4 GiB — KeyDerivation's interop max
        }
        let start = Date()
        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: serialized, passphrase: passphrase)) { error in
            XCTAssertEqual(error as? VaultError, .corruptDocument)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
    }

    /// FI-08: a header timeCost beyond UInt32.max must fail typed rather than
    /// silently truncate at the KDF cast (deriving with fewer rounds than the
    /// file claims — I-01 family).
    func testTamperedHeaderTimeCostTruncationRejected() throws {
        let serialized = try tamperedV2(passphrase: passphrase) {
            $0.kdfTimeCost = Int(UInt32.max) + 3
        }
        XCTAssertThrowsError(try VaultService.unlock(serializedDocument: serialized, passphrase: passphrase)) { error in
            XCTAssertEqual(error as? VaultError, .corruptDocument)
        }
    }

    func testDeviceWrapUnlockPath() throws {
        let vault = try VaultService.create(passphrase: passphrase)
        try vault.add(.password, level: .auto, payload: makeRecord(title: "GitHub"))
        let data = try vault.serializedDocument()

        let deviceProvider = RawKeyWrapProvider(key: SymmetricKey(size: .bits256))
        try vault.attachDeviceWrap(using: deviceProvider)
        let withWrap = try vault.serializedDocument()

        let reopened = try VaultService.unlockWithDeviceWrap(serializedDocument: withWrap, provider: deviceProvider)
        XCTAssertEqual(try reopened.activeRecords().first?.payload.title, "GitHub")
        XCTAssertTrue(reopened.verifyChain())

        // Passphrase path still works after attaching the device wrap.
        let viaPassphrase = try VaultService.unlock(serializedDocument: withWrap, passphrase: passphrase)
        XCTAssertEqual(try viaPassphrase.activeRecords().count, 1)

        _ = data // passphrase-only document (no device wrap) is the baseline case
    }

    func testShamirRecoveryOfVaultPassphraseSecret() throws {
        // End-to-end shape of the v1.1 recovery story: a recovery secret split
        // 3-of-5 reconstructs in a fresh process state with any 3 shares.
        let recoverySecret = SecureRandom.bytes(count: 32)
        let shares = try ShamirSecretSharing.split(secret: recoverySecret, threshold: 3, totalShares: 5)

        let vault = try VaultService.create(passphrase: passphrase)
        try vault.add(.secureNote, level: .custom, payload: RecordPayload(title: "Recovery", notes: recoverySecret.base64EncodedString()))
        let data = try vault.serializedDocument()

        let recoveredSecret = try ShamirSecretSharing.combine(shares: [shares[4], shares[0], shares[2]], threshold: 3)
        XCTAssertEqual(Data(base64Encoded: recoveredSecret.base64EncodedString()), recoverySecret)

        let reopened = try VaultService.unlock(serializedDocument: data, passphrase: passphrase)
        let note = try reopened.activeRecords().first { $0.payload.title == "Recovery" }
        XCTAssertEqual(note?.payload.notes, recoverySecret.base64EncodedString())
    }
}
