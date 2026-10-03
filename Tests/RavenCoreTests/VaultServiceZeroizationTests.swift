import CryptoKit
import XCTest
@testable import RavenCore

/// Key-material zeroization tests (Phase 3 ARCH-04/D-08).
///
/// The engine's honest scrub contract: `lock()` (and `deinit`) zero the
/// authoritative key bytes via `SecureMemory.zero` before dropping them.
/// Residual transient copies (Swift `Data`/`SymmetricKey` copy semantics)
/// are a documented platform limitation — the scrub target is the resident
/// authoritative buffer, per CONCERNS.md's fix posture.
final class VaultServiceZeroizationTests: XCTestCase {

    func testLockScrubsKeyBytesAndDropsThem() throws {
        let service = try VaultService.create(passphrase: "zeroize-test")
        XCTAssertTrue(service.isUnlocked)
        XCTAssertEqual(service.lastScrubbedKeyByteCount, 0, "no scrub should have happened before the first lock")

        service.lock()

        XCTAssertEqual(service.lastScrubbedKeyByteCount, 32, "lock() must scrub the 32-byte data key via SecureMemory.zero")
        XCTAssertNil(service.dataKeyBytes, "the scrubbed buffer reference must be dropped")
        XCTAssertFalse(service.isUnlocked)
    }

    func testSecondLockIsANoOpScrub() throws {
        let service = try VaultService.create(passphrase: "zeroize-twice")
        service.lock()
        XCTAssertEqual(service.lastScrubbedKeyByteCount, 32)

        service.lock()
        XCTAssertEqual(service.lastScrubbedKeyByteCount, 0, "locking an already-locked vault scrubs nothing (idempotent)")
        XCTAssertFalse(service.isUnlocked)
    }

    func testUnlockAfterLockStillWorks() throws {
        let created = try VaultService.create(passphrase: "zeroize-roundtrip")
        let serialized = try created.serializedDocument()
        created.lock()

        let reopened = try VaultService.unlock(serializedDocument: serialized, passphrase: "zeroize-roundtrip")
        XCTAssertTrue(reopened.isUnlocked)
        XCTAssertNotNil(reopened.dataKeyBytes)

        reopened.lock()
        XCTAssertEqual(reopened.lastScrubbedKeyByteCount, 32)
        XCTAssertFalse(reopened.isUnlocked)
    }

    func testDeviceWrapUnlockAlsoScrubsOnLock() throws {
        let created = try VaultService.create(passphrase: "device-wrap-scrub")
        let key = SymmetricKey(size: .bits256)
        try created.attachDeviceWrap(using: RawKeyWrapProvider(key: key))
        let serialized = try created.serializedDocument()
        created.lock()

        let reopened = try VaultService.unlockWithDeviceWrap(serializedDocument: serialized, provider: RawKeyWrapProvider(key: key))
        XCTAssertTrue(reopened.isUnlocked)
        XCTAssertEqual(reopened.dataKeyBytes?.count, 32)

        reopened.lock()
        XCTAssertEqual(reopened.lastScrubbedKeyByteCount, 32, "the device-wrap path stores scrubbed bytes too")
    }
}
