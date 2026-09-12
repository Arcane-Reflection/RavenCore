import XCTest
@testable import RavenCore

/// Salsa20 against independent-oracle vectors (pycryptodome 3.x Salsa20,
/// generated on the dev machine — eSTREAM-compatible 20-round variant).
final class Salsa20Tests: XCTestCase {

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    func testOracleVectors() throws {
        // Oracle vector 1: key = 0x80 followed by zeros, all-zero nonce.
        let v1 = try Salsa20(key: Data([0x80] + [UInt8](repeating: 0, count: 31)), nonce: Data(repeating: 0, count: 8))
        var s1 = v1
        XCTAssertEqual(hex(s1.apply(Data(repeating: 0, count: 64))),
                       "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844" +
                       "b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117")

        // Oracle vector 2: key = 1..32, nonce = 3,1,4,1,5,9,2,6.
        let v2 = try Salsa20(key: Data((1...32).map { UInt8($0) }), nonce: Data([3, 1, 4, 1, 5, 9, 2, 6]))
        var s2 = v2
        XCTAssertEqual(hex(s2.apply(Data(repeating: 0, count: 64))),
                       "6ebcbdbf76fccc64ab05542bee8a67cbc28fa2e141fbefbb3a2f9b221909c8d7" +
                       "d4295258cb539770dd24d7ac3443769ffa27a50e60644264dc8b6b612683372e")
    }

    func testRunningStreamEqualsOneShot() throws {
        let key = Data((1...32).map { UInt8($0) })
        let nonce = Data([3, 1, 4, 1, 5, 9, 2, 6])
        let message = Data("pack my box with five dozen liquor jugs".utf8)

        var oneShot = try Salsa20(key: key, nonce: nonce)
        let whole = oneShot.apply(message)

        var segmented = try Salsa20(key: key, nonce: nonce)
        XCTAssertEqual(segmented.apply(message.prefix(11)) + segmented.apply(message.dropFirst(11)), whole)
    }
}
