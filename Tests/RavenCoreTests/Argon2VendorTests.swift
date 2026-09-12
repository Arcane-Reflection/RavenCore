import CryptoKit
import XCTest
@testable import RavenCore

/// Argon2id correctness.
///
/// Validation chain (performed at vendor time, see Sources/CArgon2/UPSTREAM.md):
/// 1. The vendored C core was verified against the **RFC 9106 §5.3 Argon2id
///    test vector** via a standalone C driver (argon2_ctx with secret+AD):
///    tag = 0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659 ✓
/// 2. The Swift wrapper below was verified byte-identical to direct C calls
///    (argon2id_hash_raw) for the vectors pinned here.
final class Argon2VendorTests: XCTestCase {

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// Values confirmed by direct invocation of the vendored C at vendor time
    /// (same call path the Swift wrapper uses).
    func testReferenceVectors() throws {
        let vectors: [(password: String, salt: String, t: Int, m: Int, p: Int, expected: String)] = [
            ("password", "somesalt", 2, 65_536, 4,
             "1a9677b0afe81fda7b548895e7a1bfeb8668ffc19a530e37e088a668fab1c02a"),
            ("differentpassword", "somesalt", 2, 65_536, 4,
             "408bba26269f5fc33c3c921972fa212ab42143108bf131fd2695b74bb9084c20"),
            ("password", "DiffSalt123", 2, 65_536, 4,
             "9cc97ed6b5cc261936933768832ec48b6c695eb3e5588bbc4e74a23d67c6b0e4"),
        ]
        for v in vectors {
            let derived = try KeyDerivation.argon2id(
                password: Data(v.password.utf8),
                salt: Data(v.salt.utf8),
                memoryKiB: v.m,
                timeCost: v.t,
                parallelism: v.p
            )
            XCTAssertEqual(hex(derived), v.expected, "vector mismatch for \(v.password)/\(v.salt)")
            XCTAssertEqual(derived.count, 32)
        }
    }

    /// Golden vector for D-01 defaults (64 MiB / t=3 / p=2), pinned to catch
    /// future vendor updates drifting.
    func testDefaultParametersGoldenVector() throws {
        let derived = try KeyDerivation.argon2id(
            password: Data("correct horse battery staple".utf8),
            salt: Data(repeating: 0, count: 16),
            memoryKiB: KeyDerivation.argon2MemoryKiB,
            timeCost: KeyDerivation.argon2TimeCost,
            parallelism: KeyDerivation.argon2Parallelism
        )
        XCTAssertEqual(hex(derived),
                       "029b0ef360e711efd202f2d1325203d490d3df2d71864e1443a3f4258e51c3a2")
    }

    func testParameterGuards() throws {
        let good = { memory in
            try KeyDerivation.argon2id(password: Data("pw".utf8), salt: Data(repeating: 1, count: 8),
                                       memoryKiB: memory, timeCost: 1, parallelism: 1)
        }
        // Floor = Argon2 spec minimum (8·p KiB, p = 1 here) — FW-03 aligned it
        // with the kdbx-layer clamp so desktop-created files below 8 MiB stay
        // derivable; 7 KiB is below the spec floor and still rejected.
        XCTAssertThrowsError(try good(7)) { XCTAssertEqual($0 as? KeyDerivationError, .invalidParameter) }
        _ = try good(8)
        XCTAssertThrowsError(try good(4_194_305)) { XCTAssertEqual($0 as? KeyDerivationError, .invalidParameter) }
        XCTAssertThrowsError(try KeyDerivation.argon2id(password: Data(), salt: Data(repeating: 1, count: 8),
                                                        memoryKiB: 65_536, timeCost: 1, parallelism: 1)) {
            XCTAssertEqual($0 as? KeyDerivationError, .invalidParameter)
        }
        XCTAssertThrowsError(try KeyDerivation.argon2id(password: Data("pw".utf8), salt: Data(),
                                                        memoryKiB: 65_536, timeCost: 1, parallelism: 1)) {
            XCTAssertEqual($0 as? KeyDerivationError, .invalidParameter)
        }
        XCTAssertThrowsError(try KeyDerivation.argon2id(password: Data("pw".utf8), salt: Data(repeating: 1, count: 8),
                                                        memoryKiB: 65_536, timeCost: 0, parallelism: 1)) {
            XCTAssertEqual($0 as? KeyDerivationError, .invalidParameter)
        }
        XCTAssertThrowsError(try KeyDerivation.argon2id(password: Data("pw".utf8), salt: Data(repeating: 1, count: 8),
                                                        memoryKiB: 65_536, timeCost: 1, parallelism: 17)) {
            XCTAssertEqual($0 as? KeyDerivationError, .invalidParameter)
        }
        // Deterministic: same inputs → same output; different salt → different output.
        let a = try KeyDerivation.argon2id(password: Data("pw".utf8), salt: Data(repeating: 9, count: 8),
                                           memoryKiB: 8_192, timeCost: 1, parallelism: 1)
        let b = try KeyDerivation.argon2id(password: Data("pw".utf8), salt: Data(repeating: 9, count: 8),
                                           memoryKiB: 8_192, timeCost: 1, parallelism: 1)
        let c = try KeyDerivation.argon2id(password: Data("pw".utf8), salt: Data(repeating: 8, count: 8),
                                           memoryKiB: 8_192, timeCost: 1, parallelism: 1)
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }
}
