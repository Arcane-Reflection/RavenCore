import XCTest
@testable import RavenCore

/// Semantic-fidelity harness (⟳-aware model comparison) — the ONLY comparison
/// contract for corpus round-trip tests (01-04). ⟳ fields (master seed, IV,
/// inner stream key, KDF salt, times) legitimately change on every save.
enum SemanticKdbx {

    /// Normalizes ⟳-volatile fields so two saves of the same logical content
    /// compare Equatable.
    static func normalized(_ document: KdbxDocument) -> KdbxDocument {
        var doc = document
        doc.version = .v40 // D-05: 3.1 documents upgrade to 4.0 on save
        doc.meta.settingsChanged = nil
        normalizeGroup(&doc.root)
        for i in doc.deletedObjects.indices {
            doc.deletedObjects[i].deletionTime = doc.deletedObjects[i].deletionTime.map { _ in Date(timeIntervalSince1970: 0) }
        }
        return doc
    }

    private static func normalizeGroup(_ group: inout KdbxGroup) {
        normalizeTimes(&group.times)
        for i in group.entries.indices {
            normalizeEntry(&group.entries[i])
        }
        for i in group.groups.indices {
            normalizeGroup(&group.groups[i])
        }
    }

    private static func normalizeEntry(_ entry: inout KdbxEntry) {
        normalizeTimes(&entry.times)
        for i in entry.history.indices {
            normalizeEntry(&entry.history[i])
        }
    }

    private static func normalizeTimes(_ times: inout KdbxTimes?) {
        guard var t = times else { return }
        let epoch = Date(timeIntervalSince1970: 0)
        t.creationTime = t.creationTime.map { _ in epoch }
        t.lastModificationTime = t.lastModificationTime.map { _ in epoch }
        t.lastAccessTime = t.lastAccessTime.map { _ in epoch }
        t.locationChanged = t.locationChanged.map { _ in epoch }
        t.expiryTime = t.expiryTime.map { _ in epoch }
        times = t
    }

    static func assertSemanticallyEqual(
        _ lhs: KdbxDocument, _ rhs: KdbxDocument,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertEqual(normalized(lhs), normalized(rhs), "semantic inequality", file: file, line: line)
    }
}

final class SemanticKdbxTests: XCTestCase {

    private let password = "semantic-test"

    private func makeDocument() -> KdbxDocument {
        var doc = KdbxDocument()
        doc.meta.generator = "RavenVault"
        doc.meta.customIcons = [KdbxCustomIcon(uuid: UUID(uuidString: "CCCCCCCC-0000-0000-0000-000000000001")!, pngData: Data([1, 2, 3]))]
        var entry = KdbxEntry()
        entry.setValue("Title", "Doc")
        entry.setValue("Password", "pw", protected: true)
        var old = KdbxEntry()
        old.setValue("Title", "Doc-old")
        entry.history = [old]
        doc.binaries = [KdbxInnerHeader.Binary(flags: 0, content: Data("bin".utf8))]
        entry.binaries = [KdbxBinaryReference(key: "b", ref: 0)]
        doc.root.entries.append(entry)
        doc.deletedObjects = [KdbxDeletedObject(uuid: UUID(), deletionTime: Date())]
        return doc
    }

    func testThreeRoundTripsStaySemanticallyEqual() throws {
        let reference = makeDocument()
        var document = reference
        let credentials = try KdbxReader.Credentials(password: password)
        for round in 1...3 {
            let data = try KdbxWriter.write(document, credentials: credentials)
            document = try KdbxReader.read(data, credentials: credentials)
            SemanticKdbx.assertSemanticallyEqual(reference, document)
            XCTAssertEqual(document.root.entries[0].history.count, 1, "round \(round)")
            XCTAssertEqual(document.meta.customIcons.count, 1, "round \(round)")
        }
        SemanticKdbx.assertSemanticallyEqual(reference, document)
    }

    func testHarnessDetectsRealDifferences() throws {
        var a = makeDocument()
        var b = makeDocument()
        a.root.entries[0].history[0].setValue("Title", "DIFFERENT")
        b.root.entries[0].history[0].setValue("Title", "Doc-old")
        // A mutated history title must NOT compare equal (harness has teeth).
        XCTAssertNotEqual(SemanticKdbx.normalized(a), SemanticKdbx.normalized(b))
        _ = b
    }
}
