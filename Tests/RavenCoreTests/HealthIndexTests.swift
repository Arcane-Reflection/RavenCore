import CryptoKit
import XCTest
@testable import RavenCore

/// HealthIndex engine suite (Phase 8, plan 08-01B; EXTRA-02, 08-CONTEXT
/// D-06/D-07). Fixture-first: hand-built `DecryptedRecord` inputs, a fixed
/// `now` closure for the age dimension (TOTPGeneratorTests clock style),
/// and a structural guarantee that no password material ever appears in a
/// `HealthReport` (T-08-04).
final class HealthIndexTests: XCTestCase {

    // MARK: - Fixtures

    private static let fixedNow = Date(timeIntervalSince1970: 1_800_000_000) // 2027-01-15-ish

    private func record(
        _ id: UUID,
        password: String,
        type: RecordType = .password,
        createdAt: Date,
        folderID: UUID? = nil
    ) -> DecryptedRecord {
        DecryptedRecord(
            id: id,
            createdAt: createdAt,
            type: type,
            level: .custom,
            payload: RecordPayload(title: "Fixture \(id.uuidString.prefix(4))", password: password),
            folderID: folderID,
            isArchived: false)
    }

    private func sha256Hex(_ value: String) -> String {
        Data(SHA256.hash(data: Data(value.utf8))).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Behavior 1: weak hits against the embedded corpus

    func testCorpusPasswordIsWeakHitAndHighEntropyPasswordIsNot() {
        let weakID = UUID()
        let strongID = UUID()
        let report = HealthIndex.evaluate(records: [
            record(weakID, password: "letmein", createdAt: Self.fixedNow),
            record(strongID, password: "correct horse battery staple zzz", createdAt: Self.fixedNow),
        ], now: { Self.fixedNow })

        XCTAssertEqual(report.weakHitRecordIDs, [weakID])
        XCTAssertFalse(report.weakHitRecordIDs.contains(strongID))
    }

    // MARK: - Behavior 2: reuse groups keyed by SHA-256, never plaintext

    func testSharedPasswordLandsInOneReuseGroupKeyedBySHA256WithoutPlaintext() throws {
        let firstID = UUID()
        let secondID = UUID()
        let shared = "gossaamer-hinkalgo-77"
        let report = HealthIndex.evaluate(records: [
            record(firstID, password: shared, createdAt: Self.fixedNow),
            record(secondID, password: shared, createdAt: Self.fixedNow),
        ], now: { Self.fixedNow })

        XCTAssertEqual(report.reuseGroups.count, 1)
        let group = try XCTUnwrap(report.reuseGroups.first)
        XCTAssertEqual(group.key, sha256Hex(shared), "group key is the SHA-256 of the password")
        XCTAssertEqual(
            group.recordIDs,
            [firstID, secondID].sorted { $0.uuidString < $1.uuidString },
            "members sorted canonically")
        XCTAssertFalse(
            String(describing: report).contains(shared),
            "the report structure must never carry password material (T-08-04)")
    }

    func testDistinctPasswordsProduceNoReuseGroup() {
        let report = HealthIndex.evaluate(records: [
            record(UUID(), password: "first-unique-1", createdAt: Self.fixedNow),
            record(UUID(), password: "second-unique-2", createdAt: Self.fixedNow),
        ], now: { Self.fixedNow })

        XCTAssertTrue(report.reuseGroups.isEmpty)
    }

    // MARK: - Behavior 3: age dimension with the injected clock

    func testAgeUsesInjectedClockDeterministically() {
        let id = UUID()
        let createdAt = Self.fixedNow.addingTimeInterval(-400 * 24 * 60 * 60)
        let report = HealthIndex.evaluate(
            records: [record(id, password: "unique-not-common-3", createdAt: createdAt)],
            now: { Self.fixedNow })

        XCTAssertEqual(report.passwordAgeDays[id], 400)
    }

    func testNonPasswordRecordTypesDoNotParticipate() {
        let totpID = UUID()
        let noteID = UUID()
        let report = HealthIndex.evaluate(records: [
            record(totpID, password: "letmein", type: .totp, createdAt: Self.fixedNow),
            record(noteID, password: "letmein", type: .secureNote, createdAt: Self.fixedNow),
        ], now: { Self.fixedNow })

        XCTAssertTrue(report.weakHitRecordIDs.isEmpty, "only password-bearing kinds participate")
        XCTAssertTrue(report.reuseGroups.isEmpty)
        XCTAssertTrue(report.passwordAgeDays.isEmpty)
    }

    /// The empty-password participation guard is load-bearing: without it,
    /// two empty passwords collide on SHA-256("") and forge a phantom reuse
    /// group (08 review WR-3).
    func testEmptyPasswordsNeverFormReuseGroupWeakHitOrAge() {
        let firstID = UUID()
        let secondID = UUID()
        let report = HealthIndex.evaluate(records: [
            record(firstID, password: "", createdAt: Self.fixedNow),
            record(secondID, password: "", createdAt: Self.fixedNow),
        ], now: { Self.fixedNow })

        XCTAssertTrue(report.weakHitRecordIDs.isEmpty, "empty passwords never hit the corpus")
        XCTAssertTrue(report.reuseGroups.isEmpty, "SHA-256(\"\") must never forge a reuse group")
        XCTAssertTrue(report.passwordAgeDays.isEmpty, "non-participating records carry no age")
    }

    /// A future timestamp (device clock moved back after creation) clamps
    /// to 0 days — the age dimension never lies forward (HealthIndex.
    /// ageDays clamp, 08 review).
    func testFutureCreatedAtClampsToZeroDays() {
        let id = UUID()
        let futureCreatedAt = Self.fixedNow.addingTimeInterval(30 * 24 * 60 * 60)
        let report = HealthIndex.evaluate(
            records: [record(id, password: "unique-not-common-4", createdAt: futureCreatedAt)],
            now: { Self.fixedNow })

        XCTAssertEqual(report.passwordAgeDays[id], 0, "a future createdAt reports 0, never a negative age")
    }

    // MARK: - Behavior 6 (spec-less edge): empty input

    func testEmptyInputYieldsEmptyReport() {
        let report = HealthIndex.evaluate(records: [], now: { Self.fixedNow })

        XCTAssertEqual(report, HealthIndex.HealthReport(
            weakHitRecordIDs: [], reuseGroups: [], passwordAgeDays: [:]),
            "no crash, no placeholder groups")
    }

    // MARK: - Behavior 7 (spec-less edges): adjacency + ordering

    func testSamePasswordAcrossDifferentVaultsLandsInOneReuseGroup() {
        // The engine receives the concatenated record collections; two
        // records originating from different vaults (distinct folders here)
        // must still group together — adjacency across the input boundary.
        let firstID = UUID()
        let secondID = UUID()
        let vaultAFolder = UUID()
        let vaultBFolder = UUID()
        let report = HealthIndex.evaluate(records: [
            record(firstID, password: "cross-vault-shared-9", createdAt: Self.fixedNow,
                   folderID: vaultAFolder),
            record(secondID, password: "cross-vault-shared-9", createdAt: Self.fixedNow,
                   folderID: vaultBFolder),
        ], now: { Self.fixedNow })

        XCTAssertEqual(report.reuseGroups.count, 1)
        XCTAssertEqual(report.reuseGroups.first?.recordIDs.count, 2)
    }

    func testPermutedInputOrderYieldsEqualReport() {
        let records = [
            record(UUID(), password: "letmein", createdAt: Self.fixedNow),
            record(UUID(), password: "shared-everywhere-5", createdAt: Self.fixedNow),
            record(UUID(), password: "shared-everywhere-5", createdAt: Self.fixedNow),
            record(UUID(), password: "unique-not-common-3", createdAt: Self.fixedNow),
        ]
        let forward = HealthIndex.evaluate(records: records, now: { Self.fixedNow })
        let reversed = HealthIndex.evaluate(records: records.reversed(), now: { Self.fixedNow })

        XCTAssertEqual(forward, reversed, "grouping is deterministic under input permutation")
    }
}
