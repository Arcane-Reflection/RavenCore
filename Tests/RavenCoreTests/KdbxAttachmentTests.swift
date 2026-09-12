import XCTest
@testable import RavenCore

/// CORE-05 attachments + D-07 limits: in-memory processing, 25 MiB hard cap,
/// loud errors on both read and write sides, byte-exact round trip.
final class KdbxAttachmentTests: XCTestCase {

    private let password = "attachment-test"

    func testAttachmentByteExactRoundTrip() throws {
        let content = Data((0..<1_048_576).map { UInt8(($0 * 7) % 251) }) // 1 MiB
        var doc = KdbxDocument()
        doc.binaries = [KdbxInnerHeader.Binary(flags: 0x01, content: content)]

        var entry = KdbxEntry()
        entry.setValue("Title", "WithFile")
        entry.binaries = [KdbxBinaryReference(key: "receipt.pdf", ref: 0)]
        doc.root.entries.append(entry)

        let credentials = try KdbxReader.Credentials(password: password)
        let data = try KdbxWriter.write(doc, credentials: credentials)
        let reopened = try KdbxReader.read(data, credentials: credentials)

        XCTAssertEqual(reopened.binaries.count, 1)
        XCTAssertEqual(reopened.binaries[0].content, content, "attachment bytes must survive exactly")
        XCTAssertEqual(reopened.binaries[0].isProtected, true, "flags must survive")
        XCTAssertEqual(reopened.root.entries.first?.binaries.first?.key, "receipt.pdf")
        XCTAssertEqual(reopened.root.entries.first?.binaries.first?.ref, 0)
    }

    func testWriteSideOverLimitThrowsLoudly() throws {
        var doc = KdbxDocument()
        doc.binaries = [
            KdbxInnerHeader.Binary(flags: 0, content: Data(repeating: 1, count: KdbxAttachments.sizeLimitBytes + 1)),
        ]
        let credentials = try KdbxReader.Credentials(password: password)
        XCTAssertThrowsError(try KdbxWriter.write(doc, credentials: credentials)) { error in
            XCTAssertEqual(error as? KdbxError, .attachmentTooLarge(limitBytes: KdbxAttachments.sizeLimitBytes))
        }
    }

    /// FI-07: entry refs that do not index the pool are a loud error, not a
    /// silently-corrupt file other readers may reject. The documented
    /// `binaries` precondition becomes enforced rather than advisory.
    func testDanglingBinaryRefThrowsLoudly() throws {
        var doc = KdbxDocument()
        doc.binaries = [KdbxInnerHeader.Binary(flags: 0x01, content: Data("a".utf8))]

        var entry = KdbxEntry()
        entry.setValue("Title", "Dangling")
        entry.binaries = [KdbxBinaryReference(key: "x.bin", ref: 3)] // pool has 1
        doc.root.entries.append(entry)

        let credentials = try KdbxReader.Credentials(password: password)
        XCTAssertThrowsError(try KdbxWriter.write(doc, credentials: credentials)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
    }

    /// FI-07: negative refs (parsable from hostile files) are rejected on
    /// write as well.
    func testNegativeBinaryRefThrowsLoudly() throws {
        var doc = KdbxDocument()
        var entry = KdbxEntry()
        entry.setValue("Title", "Negative")
        entry.binaries = [KdbxBinaryReference(key: "x.bin", ref: -5)]
        doc.root.entries.append(entry)

        let credentials = try KdbxReader.Credentials(password: password)
        XCTAssertThrowsError(try KdbxWriter.write(doc, credentials: credentials)) { error in
            XCTAssertEqual(error as? KdbxError, .malformedData)
        }
    }

    func testReadSideCraftedHugeBinaryRejectedWithoutAllocation() throws {
        // Craft an inner header declaring a 100 MiB binary; the reader must
        // reject it before retaining content.
        var inner = ByteWriter()
        var streamID = ByteWriter()
        streamID.writeInt32(3)
        func emit(_ w: inout ByteWriter, _ id: UInt8, _ v: Data) {
            w.writeUInt8(id)
            w.writeInt32(Int32(v.count))
            w.writeBytes(v)
        }
        emit(&inner, 1, streamID.data)
        var key = ByteWriter()
        key.writeBytes(SecureRandom.bytes(count: 64))
        emit(&inner, 2, key.data)
        // Declare the length without materializing 100 MiB of real content —
        // the reader's length precheck must fire before any allocation.
        inner.writeUInt8(3)
        inner.writeInt32(Int32(100 * 1_048_576) + 1)
        inner.writeBytes(Data(repeating: 0, count: 64)) // truncated body; precheck fires first
        inner.writeUInt8(0)
        inner.writeInt32(0)

        var payload = inner.data
        payload.append(Data("<KeePassFile></KeePassFile>".utf8))
        XCTAssertThrowsError(try KdbxInnerHeader.read(payload)) { error in
            XCTAssertEqual(error as? KdbxError, .attachmentTooLarge(limitBytes: KdbxAttachments.sizeLimitBytes))
        }
    }
}
