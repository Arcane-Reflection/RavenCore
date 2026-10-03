import CryptoKit
import Foundation

/// Errors thrown by `MirrorContainer`. All `Equatable` for exact-case test
/// assertions; associated values exist for the ENGINE surface only
/// (`versionUnsupported`, `channelUnknown`) — the app's `ErrorMapper`
/// mapping stays value-free (no byte values ever reach user copy,
/// T-07-03-04).
public enum MirrorError: Error, Equatable {
    /// The 4-byte magic is not `RVMI` — not a RavenVault mirror at all.
    case magicMismatch
    /// The container's format version is newer than this build understands.
    case versionUnsupported(UInt8)
    /// The header's KDF id is not Argon2id (0x01).
    case kdfUnsupported(UInt8)
    /// GCM authentication failed — wrong passphrase or tampered bytes.
    /// Unified with the wrong-passphrase case on purpose (D-06): the decode
    /// never reveals which half failed.
    case authenticationFailed
    /// Structural failure (undersized header, payload-length mismatch,
    /// blob framing overrun).
    case malformed
    /// A payload blob carries an id this build does not know.
    case channelUnknown(UInt8)
}

/// A payload channel inside a mirror container (D-06: the mirror carries
/// BOTH export formats — interop recovery via kdbx, full-fidelity recovery
/// via the native format).
public enum MirrorChannel: UInt8, Sendable, CaseIterable, Comparable {
    /// The `.kdbx` export (interop channel; lossy, research R9).
    case kdbx = 0x01
    /// The `.ravenvault` native serialization (full-fidelity channel).
    case ravenvault = 0x02

    public static func < (lhs: MirrorChannel, rhs: MirrorChannel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// The Secure Mirror encrypted container codec (07-CONTEXT D-06, RECOV-03).
///
/// A mirror is ONE file carrying the whole vault (minus Emergency Cards —
/// excluded by the exporter before either channel is serialized, D-16) as
/// two length-prefixed blobs, sealed with AES-256-GCM under an Argon2id
/// key derived from a user-chosen mirror passphrase (independent of the
/// vault passphrase, D-07). The header is self-describing and versioned
/// (same posture as `VaultHeader`): KDF parameters travel in the file, and
/// the version byte is reserved for additive-only evolution — a published
/// backup contract (Docs/MIRROR-FORMAT.md is the public spec; the vectors
/// in Docs/TEST-VECTORS/mirror-v1.json are frozen).
///
/// Layout (big-endian throughout):
///
///     offset  size  field
///     0       4     magic "RVMI"
///     4       2     container version (u16, starts at 1)
///     6       1     KDF id (0x01 = Argon2id)
///     7       4     memoryKiB (u32)
///     11      1     timeCost
///     12      1     parallelism
///     13      16    KDF salt
///     29      8     payload length (u64)
///     37      12    GCM nonce (from SealedPayload — never manual)
///     49      ...   GCM ciphertext || 16-byte tag
///
/// Plaintext payload framing (a sequence of blobs, ascending channel id):
///
///     [1 byte channel id][8 bytes blob length][blob bytes]
///
/// Crypto policy: KDF = `KeyDerivation.argon2id` at the pinned engine
/// constants (a parameter change breaks the tests, not users' mirrors);
/// AEAD = `AESGCMCipher` (CryptoKit GCM) only — never any other GCM
/// implementation, and never a manually constructed nonce.
/// Authenticate-before-parse: magic, version
/// and KDF id are checked, then GCM failure short-circuits ALL payload
/// parsing (T-07-03-01) — no blob byte is interpreted before the tag
/// verifies.
public enum MirrorContainer {

    /// ASCII "RVMI".
    public static let magic = Data("RVMI".utf8)
    /// Current container version (additive-only policy, Docs/MIRROR-FORMAT.md §3).
    public static let version: UInt16 = 1
    /// Argon2id (the only KDF id defined).
    public static let kdfID: UInt8 = 0x01
    /// Fixed header byte length (see layout above).
    public static let headerLength = 49
    /// Required KDF salt length.
    public static let saltLength = 16

    // MARK: - Encrypt

    /// Serializes and seals the channel blobs under `passphrase` and `salt`.
    ///
    /// The salt is caller-supplied so tests pin it in vectors; production
    /// callers MUST pass a fresh 16-byte `SecureRandom` salt per export
    /// (T-07-03-02). Channels serialize in ascending raw-value order, which
    /// makes the container byte-deterministic for a fixed
    /// (passphrase, salt, payloads) triple — the property the frozen
    /// vectors rely on.
    public static func encrypt(
        payloads: [MirrorChannel: Data],
        passphrase: String,
        salt: Data
    ) throws -> Data {
        guard !passphrase.isEmpty else { throw MirrorError.malformed }
        guard salt.count == saltLength else { throw MirrorError.malformed }
        let key = try deriveKey(passphrase: passphrase, salt: salt)
        let sealed = try AESGCMCipher.encrypt(frame(payloads: payloads), key: key)

        var bytes: [UInt8] = []
        bytes.append(contentsOf: [0x52, 0x56, 0x4D, 0x49]) // "RVMI"
        bytes.append(contentsOf: [UInt8(version >> 8), UInt8(version & 0xFF)])
        bytes.append(kdfID)
        let memory = UInt32(KeyDerivation.argon2MemoryKiB)
        bytes.append(contentsOf: [
            UInt8(memory >> 24 & 0xFF), UInt8(memory >> 16 & 0xFF),
            UInt8(memory >> 8 & 0xFF), UInt8(memory & 0xFF)])
        bytes.append(UInt8(KeyDerivation.argon2TimeCost))
        bytes.append(UInt8(KeyDerivation.argon2Parallelism))
        bytes.append(contentsOf: salt)
        var length = UInt64(sealed.ciphertext.count)
        var lengthBytes = [UInt8](repeating: 0, count: 8)
        for index in stride(from: 7, through: 0, by: -1) {
            lengthBytes[index] = UInt8(length & 0xFF)
            length >>= 8
        }
        bytes.append(contentsOf: lengthBytes)
        bytes.append(contentsOf: [UInt8](sealed.nonce))
        bytes.append(contentsOf: [UInt8](sealed.ciphertext))
        return Data(bytes)
    }

    // MARK: - Decrypt

    /// Opens a container and returns its channel blobs. Every failure is
    /// typed and fail-closed; `authenticationFailed` covers both a wrong
    /// passphrase and tampered ciphertext bytes (unified on purpose).
    public static func decrypt(
        _ container: Data,
        passphrase: String
    ) throws -> [MirrorChannel: Data] {
        // Normalize slices (a caller may hand us `data.dropLast(n)`) so the
        // absolute offsets below are always zero-based.
        let info = try parseHeader(Data(container))
        let key = try deriveKey(
            passphrase: passphrase, salt: info.info.salt,
            memoryKiB: Int(info.info.memoryKiB), timeCost: Int(info.info.timeCost),
            parallelism: Int(info.info.parallelism))
        let sealed = SealedPayload(nonce: info.nonce, ciphertext: info.ciphertext)
        let payload: Data
        do {
            payload = try AESGCMCipher.decrypt(sealed, key: key)
        } catch {
            throw MirrorError.authenticationFailed
        }
        return try parseBlobs(payload)
    }

    // MARK: - Header introspection (honest-report surface)

    /// The self-describing header fields of a container — parsed WITHOUT a
    /// passphrase so the restore flow can describe the file honestly before
    /// asking for one. Structural checks run (magic/version/KDF id/lengths)
    /// but the payload is never touched.
    public struct HeaderInfo: Sendable, Equatable {
        /// Container format version (≤ `MirrorContainer.version`).
        public let version: UInt16
        /// KDF identifier byte (only the pinned engine KDF is accepted).
        public let kdfID: UInt8
        /// Argon2 memory cost in KiB, as self-described by the header.
        public let memoryKiB: UInt32
        /// Argon2 time cost, as self-described by the header.
        public let timeCost: UInt8
        /// Argon2 parallelism, as self-described by the header.
        public let parallelism: UInt8
        /// KDF salt (16 bytes).
        public let salt: Data
        /// Declared ciphertext length; verified to equal the actual body.
        public let payloadLength: UInt64
    }

    /// Reads a container's header (no passphrase, no payload decryption).
    public static func header(of container: Data) throws -> HeaderInfo {
        try parseHeader(Data(container)).info
    }

    // MARK: - Internals

    private struct ParsedHeader {
        let info: HeaderInfo
        let nonce: Data
        let ciphertext: Data
    }

    private static func parseHeader(_ container: Data) throws -> ParsedHeader {
        guard container.count >= headerLength else { throw MirrorError.malformed }
        guard container.prefix(4) == magic else { throw MirrorError.magicMismatch }
        let version = UInt16BE(container, at: 4)
        guard version <= MirrorContainer.version else {
            throw MirrorError.versionUnsupported(UInt8(version & 0xFF))
        }
        let kdf = container[6]
        guard kdf == kdfID else { throw MirrorError.kdfUnsupported(kdf) }
        let info = HeaderInfo(
            version: version,
            kdfID: kdf,
            memoryKiB: UInt32BE(container, at: 7),
            timeCost: container[11],
            parallelism: container[12],
            salt: container.subdata(in: 13..<29),
            payloadLength: UInt64BE(container, at: 29))
        let nonce = container.subdata(in: 37..<49)
        let ciphertext = container.count == headerLength
            ? Data()
            : container.subdata(in: 49..<container.count)
        // Declared length must match the actual body — a truncated or
        // padded container is malformed, never silently accepted.
        guard info.payloadLength == UInt64(ciphertext.count) else {
            throw MirrorError.malformed
        }
        return ParsedHeader(info: info, nonce: nonce, ciphertext: ciphertext)
    }

    private static func frame(payloads: [MirrorChannel: Data]) -> Data {
        var framed = Data()
        for channel in MirrorChannel.allCases.sorted() {
            guard let blob = payloads[channel] else { continue }
            framed.append(channel.rawValue)
            var length = UInt64(blob.count)
            var lengthBytes = [UInt8](repeating: 0, count: 8)
            for index in stride(from: 7, through: 0, by: -1) {
                lengthBytes[index] = UInt8(length & 0xFF)
                length >>= 8
            }
            framed.append(contentsOf: lengthBytes)
            framed.append(blob)
        }
        return framed
    }

    private static func parseBlobs(_ payload: Data) throws -> [MirrorChannel: Data] {
        var result: [MirrorChannel: Data] = [:]
        var index = payload.startIndex
        while index < payload.endIndex {
            guard payload.distance(from: index, to: payload.endIndex) >= 9 else {
                throw MirrorError.malformed
            }
            let id = payload[index]
            guard let channel = MirrorChannel(rawValue: id) else {
                throw MirrorError.channelUnknown(id)
            }
            let length = UInt64BE(payload, at: payload.distance(from: payload.startIndex, to: index) + 1)
            index = payload.index(index, offsetBy: 9)
            guard length <= UInt64(payload.distance(from: index, to: payload.endIndex)) else {
                throw MirrorError.malformed // blob length overrun
            }
            let blobEnd = payload.index(index, offsetBy: Int(length))
            result[channel] = payload.subdata(in: index..<blobEnd)
            index = blobEnd
        }
        return result
    }

    /// KDF at the pinned engine constants for encrypt; decrypt honors the
    /// header's self-describing parameters (within `KeyDerivation` guards).
    private static func deriveKey(
        passphrase: String,
        salt: Data,
        memoryKiB: Int = KeyDerivation.argon2MemoryKiB,
        timeCost: Int = KeyDerivation.argon2TimeCost,
        parallelism: Int = KeyDerivation.argon2Parallelism
    ) throws -> SymmetricKey {
        let bytes = try KeyDerivation.argon2id(
            password: Data(passphrase.utf8), salt: salt,
            memoryKiB: memoryKiB, timeCost: timeCost, parallelism: parallelism)
        return SymmetricKey(data: bytes)
    }

    // Big-endian readers (Foundation's Codable is not byte-stable enough
    // for a published wire contract — explicit widths only).
    private static func UInt16BE(_ data: Data, at offset: Int) -> UInt16 {
        (UInt16(data[data.startIndex + offset]) << 8) | UInt16(data[data.startIndex + offset + 1])
    }
    private static func UInt32BE(_ data: Data, at offset: Int) -> UInt32 {
        (0..<4).reduce(0) { acc, i in
            (acc << 8) | UInt32(data[data.startIndex + offset + i])
        }
    }
    private static func UInt64BE(_ data: Data, at offset: Int) -> UInt64 {
        (0..<8).reduce(0) { acc, i in
            (acc << 8) | UInt64(data[data.startIndex + offset + i])
        }
    }
}
