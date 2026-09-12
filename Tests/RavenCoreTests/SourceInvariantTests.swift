import XCTest
@testable import RavenCore

/// Source-level security invariants whose failure paths cannot be triggered
/// through the public API (they are unreachable with valid arguments), so they
/// are pinned against the source text itself — the honest minimal regression
/// for latent memory-safety guards (02-REVIEW-FULL FW-02/FW-04).
final class SourceInvariantTests: XCTestCase {

    private func source(_ relativePath: String) throws -> String {
        // <package>/Tests/RavenCoreTests/<this file> → <package>/Sources/…
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/RavenCoreTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // package root
        return try String(contentsOf: packageRoot.appendingPathComponent(relativePath), encoding: .utf8)
    }

    /// FW-02: `aesKdf` must release its `CCCryptorRef` exactly once — via the
    /// single `defer`. An explicit `CCCryptorRelease` inside the update-error
    /// guard would double-free the C opaque handle (undefined behavior) if
    /// `CCCryptorUpdate` ever failed; the `defer` already owns cleanup.
    func testAesKdfReleasesCryptorExactlyOnce() throws {
        let source = try self.source("Sources/RavenCore/Crypto/AESECBCipher.swift")
        let occurrences = source.components(separatedBy: "CCCryptorRelease").count - 1
        XCTAssertEqual(occurrences, 1, "aesKdf cryptor cleanup must stay single-ownership (one defer, no explicit release)")
    }

    /// FW-04: `SecRandomCopyBytes` status must be checked — an ignored status
    /// (`_ =`) would silently return deterministic all-zero key material on
    /// RNG failure (fail-open). The response is an abort, so the public API
    /// cannot be forced to surface it; the source assertion is the honest
    /// minimal regression.
    func testSecureRandomChecksSystemRNGStatus() throws {
        let source = try self.source("Sources/RavenCore/Crypto/SecureMemory.swift")
        XCTAssertTrue(source.contains("let status = data.withUnsafeMutableBytes"),
                      "SecRandomCopyBytes status must be captured")
        XCTAssertTrue(source.contains("status == errSecSuccess"),
                      "SecRandomCopyBytes status must be checked (fail closed)")
        XCTAssertFalse(source.contains("_ = data.withUnsafeMutableBytes"),
                       "SecRandomCopyBytes status must not be discarded")
    }
}
