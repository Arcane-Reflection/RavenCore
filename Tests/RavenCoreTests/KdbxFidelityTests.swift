import XCTest
@testable import RavenCore

/// CORE-03 fidelity: history, CustomData, custom icons, recycle-bin metadata
/// and DeletedObjects survive the write→read round trip; history-internal
/// protected values keep the document-order stream aligned.
final class KdbxFidelityTests: XCTestCase {

    private let password = "fidelity-test"

    private func makeFullDocument() -> KdbxDocument {
        var doc = KdbxDocument()
        doc.meta.generator = "RavenVault"
        doc.meta.databaseName = "Fidelity"
        doc.meta.recycleBinEnabled = true
        doc.meta.recycleBinUUID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")
        doc.meta.historyMaxItems = -1
        doc.meta.historyMaxSize = -1
        doc.meta.customIcons = [
            KdbxCustomIcon(
                uuid: UUID(uuidString: "CCCCCCCC-0000-0000-0000-000000000001")!,
                pngData: Data([0x89, 0x50, 0x4E, 0x47, 0x01, 0x02, 0x03])
            ),
        ]
        doc.meta.customData = ["Plugin_Key": "plugin-value"]

        var times = KdbxTimes()
        times.creationTime = Date(timeIntervalSince1970: 1_600_000_000)
        times.lastModificationTime = Date(timeIntervalSince1970: 1_700_000_000)
        times.expires = false

        var root = KdbxGroup(name: "Root")
        root.times = times
        root.customData = ["GroupMeta": "v1"]

        var entry = KdbxEntry()
        entry.customIconUUID = doc.meta.customIcons[0].uuid
        entry.times = times
        entry.setValue("Title", "Main")
        entry.setValue("Password", "main-secret", protected: true)
        entry.customData = ["EntryMeta": "x"]

        // Two historical revisions, one with its own protected value.
        var old1 = KdbxEntry()
        old1.setValue("Title", "Main (old)")
        old1.setValue("Password", "old-secret-1", protected: true)
        var old2 = KdbxEntry()
        old2.setValue("Title", "Main (older)")
        old2.times = times
        entry.history = [old1, old2]

        root.entries.append(entry)
        doc.root = root
        doc.deletedObjects = [
            KdbxDeletedObject(
                uuid: UUID(uuidString: "DDDDDDDD-0000-0000-0000-00000000000D")!,
                deletionTime: Date(timeIntervalSince1970: 1_750_000_000)
            ),
        ]
        return doc
    }

    func testFullFeatureRoundTrip() throws {
        let original = makeFullDocument()
        let credentials = try KdbxReader.Credentials(password: password)
        let data = try KdbxWriter.write(original, credentials: credentials)
        let reopened = try KdbxReader.read(data, credentials: credentials)

        // Meta fidelity
        XCTAssertEqual(reopened.meta.recycleBinEnabled, true)
        XCTAssertEqual(reopened.meta.recycleBinUUID, original.meta.recycleBinUUID)
        XCTAssertEqual(reopened.meta.historyMaxItems, -1)
        XCTAssertEqual(reopened.meta.customIcons, original.meta.customIcons)
        XCTAssertEqual(reopened.meta.customData, original.meta.customData)

        // Group CustomData
        XCTAssertEqual(reopened.root.customData, ["GroupMeta": "v1"])

        // Entry fidelity: icon reference, CustomData, history depth/content
        let entry = try XCTUnwrap(reopened.root.entries.first)
        XCTAssertEqual(entry.customIconUUID, original.meta.customIcons[0].uuid)
        XCTAssertEqual(entry.customData, ["EntryMeta": "x"])
        XCTAssertEqual(entry.history.count, 2)
        XCTAssertEqual(entry.history[0].value("Title"), "Main (old)")
        XCTAssertEqual(entry.history[1].value("Title"), "Main (older)")

        // DeletedObjects fidelity
        XCTAssertEqual(reopened.deletedObjects, original.deletedObjects)

        // History-internal protected value decrypts correctly — the protection
        // stream advanced through main entry AND history in document order.
        XCTAssertEqual(entry.history[0].value("Password"), "old-secret-1")
        XCTAssertEqual(entry.value("Password"), "main-secret")
    }

    func testHistoryIsTypedEquatableThroughThreeRoundTrips() throws {
        var document = makeFullDocument()
        let credentials = try KdbxReader.Credentials(password: password)
        for round in 1...3 {
            let data = try KdbxWriter.write(document, credentials: credentials)
            document = try KdbxReader.read(data, credentials: credentials)
            XCTAssertEqual(document.root.entries.first?.history.count, 2, "round \(round)")
            XCTAssertEqual(document.meta.customIcons.count, 1, "round \(round)")
        }
    }

    /// KDBX4 base64 dates are Int64-LE seconds since 0001-01-01 and must map
    /// onto the **Unix** epoch (261003-mk7 second-pass review: the decoded
    /// value was fed to `timeIntervalSinceReferenceDate`, shifting every
    /// KeePassXC-authored timestamp +31 years). ISO text (3.1) stays exact.
    func testParseDateBase64UsesUnixEpoch() throws {
        let unix = 1_767_225_600 // 2026-01-01T00:00:00Z
        var writer = ByteWriter()
        writer.writeUInt64(UInt64(unix) + 62_135_596_800) // seconds since 0001-01-01
        let base64 = writer.data.base64EncodedString()

        XCTAssertEqual(KdbxXML.Reader.parseDate(base64), Date(timeIntervalSince1970: TimeInterval(unix)))
        XCTAssertEqual(KdbxXML.Reader.parseDate("2026-01-01T00:00:00Z"), Date(timeIntervalSince1970: TimeInterval(unix)))
        XCTAssertNil(KdbxXML.Reader.parseDate("not-a-date"))
    }
}
