import XCTest
@testable import RavenCore

/// D-06 opaque preservation: unknown subtrees and unknown attributes on
/// recognized elements survive a write→read→write round trip structurally.
final class KdbxOpaqueTests: XCTestCase {

    private let password = "opaque-test"

    func testUnknownSubtreeAndAttributesSurviveRoundTrip() throws {
        // Build a document whose entry/group/meta carry unknown content by
        // parsing a synthetic XML fragment into the model via a full kdbx
        // write/read cycle: simplest reliable route is to write the unknown
        // content INTO the XML by injecting opaque nodes post-read.
        let credentials = try KdbxReader.Credentials(password: password)
        var doc = KdbxDocument()
        doc.meta.generator = "RavenVault"

        var group = KdbxGroup(name: "G")
        var entry = KdbxEntry()
        entry.setValue("Title", "T")
        // Unknown element + unknown attributes, injected as model content.
        entry.unknownXml = [
            OpaqueNode(
                name: "KeePassXC-Custom-Thing",
                attributes: [OpaqueAttribute(name: "Version", value: "2")],
                text: "payload",
                children: [
                    OpaqueNode(name: "Nested", attributes: [], text: "inner", children: []),
                ]
            ),
        ]
        entry.unknownAttributes = [OpaqueAttribute(name: "CustomAttr", value: "yes")]
        group.entries.append(entry)
        doc.root = group

        let data = try KdbxWriter.write(doc, credentials: credentials)
        let reopened = try KdbxReader.read(data, credentials: credentials)
        let entry2 = try XCTUnwrap(reopened.root.entries.first)

        XCTAssertEqual(entry2.unknownAttributes.first?.name, "CustomAttr")
        XCTAssertEqual(entry2.unknownAttributes.first?.value, "yes")
        let node = try XCTUnwrap(entry2.unknownXml.first)
        XCTAssertEqual(node.name, "KeePassXC-Custom-Thing")
        XCTAssertEqual(node.attributes.first?.value, "2")
        XCTAssertEqual(node.text, "payload")
        XCTAssertEqual(node.children.first?.name, "Nested")
        XCTAssertEqual(node.children.first?.text, "inner")

        // Second write→read: opaque content is stable (no drift).
        let data2 = try KdbxWriter.write(reopened, credentials: credentials)
        let reopened2 = try KdbxReader.read(data2, credentials: credentials)
        XCTAssertEqual(reopened2.root.entries.first?.unknownXml, entry2.unknownXml)
        XCTAssertEqual(reopened2.root.entries.first?.unknownAttributes, entry2.unknownAttributes)
    }

    /// FI-05: nesting beyond the reader's depth cap fails as a typed error
    /// instead of recursing unboundedly in opaque-subtree conversion (the XML
    /// is post-authentication, so this is defense-in-depth against stack
    /// exhaustion).
    func testExcessiveNestingRejected() throws {
        let deep = "<KeePassFile><Meta><CustomData>"
            + String(repeating: "<Zap>", count: KdbxXML.Reader.maxDepth + 400)
            + String(repeating: "</Zap>", count: KdbxXML.Reader.maxDepth + 400)
            + "</CustomData></Meta></KeePassFile>"
        let reader = KdbxXML.Reader(data: Data(deep.utf8), protectedStream: nil)
        XCTAssertThrowsError(try reader.parse()) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }
    }

    /// FI-05: deep-but-legal nesting (well under the cap) still parses and
    /// preserves the opaque subtree — the cap rejects hostile documents, not
    /// unusual-but-valid ones.
    func testDeepOpaqueSubtreeUnderCapParses() throws {
        let depth = 50
        let xml = "<KeePassFile><Root><Group><Name>G</Name>"
            + "<Entry><Tags>v</Tags>"
            + String(repeating: "<Zap>", count: depth) + "x"
            + String(repeating: "</Zap>", count: depth)
            + "</Entry></Group></Root></KeePassFile>"
        let reader = KdbxXML.Reader(data: Data(xml.utf8), protectedStream: nil)
        let document = try reader.parse()
        let entry = try XCTUnwrap(document.root.entries.first)
        let node = try XCTUnwrap(entry.unknownXml.first)
        XCTAssertEqual(node.name, "Zap")
        var current = node
        for _ in 1..<depth { current = try XCTUnwrap(current.children.first) }
        XCTAssertEqual(current.text, "x")
    }

    /// FI-09: a present-but-unparseable Entry/Group UUID is a corrupt file —
    /// identity is never silently reinvented with a fresh random UUID (which
    /// would quietly rewrite entry identity on the next save).
    func testCorruptIdentityUUIDRejected() {
        let entryXml = "<KeePassFile><Root><Group><Name>G</Name>"
            + "<Entry><UUID>!!!not-base64!!!</UUID><Tags>v</Tags></Entry>"
            + "</Group></Root></KeePassFile>"
        XCTAssertThrowsError(try KdbxXML.Reader(data: Data(entryXml.utf8), protectedStream: nil).parse()) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }

        // Wrong byte count is equally corrupt (UUIDs are 16 bytes).
        let groupXml = "<KeePassFile><Root><Group>"
            + "<UUID>" + Data(repeating: 0xAB, count: 8).base64EncodedString() + "</UUID>"
            + "<Name>G</Name></Group></Root></KeePassFile>"
        XCTAssertThrowsError(try KdbxXML.Reader(data: Data(groupXml.utf8), protectedStream: nil).parse()) { error in
            XCTAssertEqual(error as? KdbxError, .corruptFile)
        }
    }

    /// FI-09: valid identity UUIDs keep parsing (the corruption guard rejects
    /// broken files, not unusual-but-valid ones).
    func testValidIdentityUUIDParses() throws {
        let uuidData = Data((0..<16).map { UInt8($0) })
        let xml = "<KeePassFile><Root><Group>"
            + "<UUID>" + uuidData.base64EncodedString() + "</UUID><Name>G</Name>"
            + "<Entry><UUID>" + uuidData.base64EncodedString() + "</UUID><Tags>v</Tags></Entry>"
            + "</Group></Root></KeePassFile>"
        let document = try KdbxXML.Reader(data: Data(xml.utf8), protectedStream: nil).parse()
        XCTAssertEqual(document.root.uuid.data, uuidData)
        XCTAssertEqual(document.root.entries.first?.uuid.data, uuidData)
    }
}
