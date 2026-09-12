import XCTest
@testable import RavenCore

final class ShamirSecretSharingTests: XCTestCase {

    private func randomSecret(_ length: Int) -> Data {
        SecureRandom.bytes(count: length)
    }

    func testThreeOfFiveRoundTrip() throws {
        let secret = randomSecret(64)
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 3, totalShares: 5)
        XCTAssertEqual(shares.count, 5)
        XCTAssertEqual(Set(shares.map(\.index)).count, 5)

        let recovered = try ShamirSecretSharing.combine(shares: Array(shares[1...3]), threshold: 3)
        XCTAssertEqual(recovered, secret)
    }

    func testEveryValidSubsetReconstructs() throws {
        let secret = randomSecret(32)
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 3, totalShares: 5)
        for first in 0..<5 {
            for second in (first + 1)..<5 {
                for third in (second + 1)..<5 {
                    let recovered = try ShamirSecretSharing.combine(
                        shares: [shares[first], shares[second], shares[third]],
                        threshold: 3
                    )
                    XCTAssertEqual(recovered, secret, "subset \(first),\(second),\(third) failed")
                }
            }
        }
    }

    func testTwoOfTwoRoundTrip() throws {
        let secret = randomSecret(16)
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 2, totalShares: 2)
        let recovered = try ShamirSecretSharing.combine(shares: shares, threshold: 2)
        XCTAssertEqual(recovered, secret)
    }

    func testBelowThresholdFails() throws {
        let shares = try ShamirSecretSharing.split(secret: randomSecret(32), threshold: 3, totalShares: 5)
        XCTAssertThrowsError(try ShamirSecretSharing.combine(shares: Array(shares.prefix(2)), threshold: 3)) { error in
            XCTAssertEqual(error as? ShamirError, .notEnoughShares)
        }
    }

    func testDuplicateShareIndexRejected() throws {
        let shares = try ShamirSecretSharing.split(secret: randomSecret(32), threshold: 2, totalShares: 3)
        let duplicated = [shares[0], shares[0]]
        XCTAssertThrowsError(try ShamirSecretSharing.combine(shares: duplicated, threshold: 2)) { error in
            XCTAssertEqual(error as? ShamirError, .invalidShares)
        }
    }

    func testInvalidConfigurationRejected() {
        let secret = randomSecret(8)
        XCTAssertThrowsError(try ShamirSecretSharing.split(secret: secret, threshold: 1, totalShares: 3))
        XCTAssertThrowsError(try ShamirSecretSharing.split(secret: secret, threshold: 4, totalShares: 3))
        XCTAssertThrowsError(try ShamirSecretSharing.split(secret: Data(), threshold: 2, totalShares: 3))
        XCTAssertThrowsError(try ShamirSecretSharing.split(secret: secret, threshold: 2, totalShares: 256))
    }

    func testMaximumShareCount() throws {
        let secret = randomSecret(8)
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 2, totalShares: 255)
        XCTAssertEqual(shares.count, 255)
        let recovered = try ShamirSecretSharing.combine(shares: [shares[0], shares[254]], threshold: 2)
        XCTAssertEqual(recovered, secret)
    }

    func testGFTablesMatchSlowMultiplication() {
        for a in UInt8.min ... UInt8.max {
            for b in [UInt8(0), 1, 2, 3, 7, 128, 255] {
                XCTAssertEqual(ShamirSecretSharing.gfMultiply(a, b), ShamirSecretSharing.multiplySlow(a, b),
                               "\(a) * \(b) mismatch")
            }
        }
        // Cross-check division as the inverse of multiplication.
        for a: UInt8 in [1, 5, 42, 200, 255] {
            for b: UInt8 in [1, 3, 77, 254] {
                XCTAssertEqual(ShamirSecretSharing.gfMultiply(ShamirSecretSharing.gfDivide(a, b), b), a)
            }
        }
    }
}
