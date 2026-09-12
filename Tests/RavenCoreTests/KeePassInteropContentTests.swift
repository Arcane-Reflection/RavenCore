import XCTest
@testable import RavenCore

/// External-oracle regression (Phase 1 UAT finding): protected values must
/// decrypt with the SPEC nonce derivation H[32..44]. The fixture is a real
/// KeePassXC-compatible KDBX 4.0 file (KDBXKit interop fixture, password "123").
final class KeePassInteropContentTests: XCTestCase {
    func testExternalKDBX4FixtureProtectedValues() throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: "/Users/umaj35ty/Projects/ios/RavenVault/Packages/RavenCore/Tests/Fixtures/External/ext-kdbxkit-simple.kdbx"))
        let creds = try KdbxReader.Credentials(password: "123")
        let doc = try KdbxReader.read(data, credentials: creds)
        print("EXT-ENTRIES:", doc.root.allEntries().count)
        for e in doc.root.allEntries() {
            for s in e.strings {
                print("EXT-FIELD [\(s.key)] protected=\(s.protected) = '\(s.value)'")
            }
        }
        let entry = try XCTUnwrap(doc.root.allEntries().reversed().first { $0.value("Password") != nil })
        XCTAssertEqual(entry.value("Password"), "mypassword") // canonical-stream plaintext (independently verified)
        // Round trip through our writer must now be KeePassXC-readable.
        let rewritten = try KdbxWriter.write(doc, credentials: creds)
        let reopened = try KdbxReader.read(rewritten, credentials: creds)
        let rt = reopened.root.allEntries().reversed().first { $0.value("Password") != nil }
        XCTAssertEqual(rt?.value("Password"), "mypassword")
    }
}
