import XCTest
@testable import RavenCore

final class AppendOnlyLogTests: XCTestCase {

    func testEmptyLogVerifies() {
        let log = AppendOnlyLog()
        XCTAssertTrue(log.verify())
        XCTAssertTrue(log.entries.isEmpty)
    }

    func testAppendProducesVerifiableChain() {
        var log = AppendOnlyLog()
        for index in 0..<5 {
            log.append(payload: Data("entry-\(index)".utf8))
        }
        XCTAssertEqual(log.entries.count, 5)
        XCTAssertTrue(log.verify())
    }

    func testTamperedPayloadDetected() {
        var log = AppendOnlyLog()
        log.append(payload: Data("keep me honest".utf8))
        log.append(payload: Data("me too".utf8))
        XCTAssertTrue(log.verify())

        let original = log.entries[0]
        let forged = VaultLogEntry(
            id: original.id,
            createdAt: original.createdAt,
            payload: Data("forged".utf8),
            previousHash: original.previousHash,
            hash: original.hash
        )
        log.entries[0] = forged
        XCTAssertFalse(log.verify())
    }

    func testTamperedHeadDetached() {
        var log = AppendOnlyLog()
        log.append(payload: Data("one".utf8))
        XCTAssertTrue(log.verify())

        log.headHash = Data(repeating: 0xAB, count: 32)
        XCTAssertFalse(log.verify())
    }

    func testArchiveDoesNotBreakChain() {
        var log = AppendOnlyLog()
        let first = log.append(payload: Data("one".utf8))
        log.append(payload: Data("two".utf8))
        XCTAssertTrue(log.archive(id: first.id))
        XCTAssertTrue(log.verify())
        XCTAssertTrue(log.entries[0].isArchived)
    }

    func testArchiveIsIdempotent() {
        var log = AppendOnlyLog()
        let entry = log.append(payload: Data("one".utf8))
        XCTAssertTrue(log.archive(id: entry.id))
        XCTAssertFalse(log.archive(id: entry.id))
    }

    func testCompactRemovesArchivedAndRebuildsChain() {
        var log = AppendOnlyLog()
        let first = log.append(payload: Data("one".utf8))
        log.append(payload: Data("two".utf8))
        let third = log.append(payload: Data("three".utf8))
        log.archive(id: first.id)

        let removed = log.compact()
        XCTAssertEqual(removed, 1)
        XCTAssertEqual(log.entries.count, 2)
        XCTAssertEqual(log.entries.map { $0.payload }, [Data("two".utf8), Data("three".utf8)])
        XCTAssertTrue(log.verify())

        // Chain still extends correctly after compaction.
        log.append(payload: Data("four".utf8))
        XCTAssertTrue(log.verify())
        XCTAssertTrue(log.archive(id: third.id))
        XCTAssertEqual(log.entries.count, 3) // archiving marks, never removes
    }

    func testCompactWithoutArchivesIsNoOp() {
        var log = AppendOnlyLog()
        log.append(payload: Data("one".utf8))
        XCTAssertEqual(log.compact(), 0)
        XCTAssertTrue(log.verify())
    }

    func testCodableRoundTripPreservesVerifiability() throws {
        var log = AppendOnlyLog()
        log.append(payload: Data("one".utf8))
        log.append(payload: Data("two".utf8))

        let data = try JSONEncoder().encode(log)
        let restored = try JSONDecoder().decode(AppendOnlyLog.self, from: data)
        XCTAssertTrue(restored.verify())
        XCTAssertEqual(restored.headHash, log.headHash)
    }
}
