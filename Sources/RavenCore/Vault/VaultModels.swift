import Foundation

/// Security tiers per the v1.1 model. v1.0's plaintext "Level 0" was removed
/// from the vault mix and became the isolated Emergency Card feature (app layer).
public enum SecurityLevel: String, Codable, Sendable, CaseIterable {
    /// L1 Auto — data key dual-wrapped by Secure Enclave + passphrase KEK.
    case auto
    /// L2 Custom — cold-storage tier, Argon2id/passphrase only, Shamir recovery.
    case custom
}

/// The kind of record a log entry carries.
public enum RecordType: String, Codable, Sendable, CaseIterable {
    case password
    case totp
    case card
    case secureNote
    case seedPhrase
}

/// The decrypted content of a vault record.
public struct RecordPayload: Sendable, Equatable, Codable {
    /// Display title (the one always-visible field).
    public var title: String
    /// Account username, if any.
    public var username: String
    /// Account password, if any.
    public var password: String
    /// Free-form notes, if any.
    public var notes: String
    /// TOTP shared secret, if any.
    public var totpSecret: String?
    /// Seed phrase words (cold-storage tier), if any.
    public var seedPhrase: [String]?

    /// Creates a payload; omitted fields default to empty/nil.
    public init(
        title: String,
        username: String = "",
        password: String = "",
        notes: String = "",
        totpSecret: String? = nil,
        seedPhrase: [String]? = nil
    ) {
        self.title = title
        self.username = username
        self.password = password
        self.notes = notes
        self.totpSecret = totpSecret
        self.seedPhrase = seedPhrase
    }
}

/// What actually gets encrypted into a log entry's payload.
struct RecordEnvelope: Codable, Sendable, Equatable {
    var type: RecordType
    var level: SecurityLevel
    var record: RecordPayload
}

/// A decrypted record surfaced to the app layer.
public struct DecryptedRecord: Sendable, Equatable, Identifiable {
    /// Record identifier.
    public let id: UUID
    /// When the record entered the log.
    public let createdAt: Date
    /// Record kind.
    public let type: RecordType
    /// Security tier.
    public let level: SecurityLevel
    /// Decrypted content.
    public let payload: RecordPayload
    /// Soft-delete state (reversible until compaction).
    public let isArchived: Bool
}

/// KDF algorithm identifiers stored in `VaultHeader.kdfAlgorithm`.
public enum VaultKDF {
    /// Argon2id — default for newly created vaults (formatVersion 2).
    public static let argon2id = "argon2id"
    /// PBKDF2-HMAC-SHA256 — version-1 format; unlock path kept forever (D-04).
    public static let pbkdf2 = "pbkdf2"
}

/// Key-wrapping parameters and wrapped data keys. Stored alongside the log.
///
/// Format notes: `kdfSalt`/`kdfIterations` date from version 1. The Argon2id
/// fields are additive (version 2, 01-CONTEXT.md D-01); decoding a version-1
/// document infers `kdfAlgorithm == pbkdf2`. Old documents must stay decodable
/// forever — only additive changes are allowed here.
public struct VaultHeader: Sendable, Equatable, Codable {
    /// Format version: 1 = PBKDF2, 2 = Argon2id parameters present.
    public var formatVersion: Int
    /// KDF salt (16 random bytes at creation).
    public var kdfSalt: Data
    /// PBKDF2 iteration count (version-1 field; also updated on upgrade).
    public var kdfIterations: Int
    /// Data key wrapped by the passphrase-derived KEK (portable path).
    public var wrappedDataKey: SealedPayload
    /// Data key wrapped by the Secure Enclave key (device path). Optional —
    /// attached later on device; its absence never blocks unlock.
    public var deviceWrappedDataKey: SealedPayload?
    /// Head hash of the log this header belongs to (integrity pairing).
    public var headHash: Data
    /// Which KDF protects `wrappedDataKey` (formatVersion 2+; inferred for v1).
    public var kdfAlgorithm: String
    /// Argon2id parameters (formatVersion 2, `kdfAlgorithm == argon2id`).
    public var kdfMemoryKiB: Int?
    /// Argon2id parallelism (formatVersion 2, `kdfAlgorithm == argon2id`).
    public var kdfParallelism: Int?
    /// Argon2id time cost (formatVersion 2, `kdfAlgorithm == argon2id`).
    public var kdfTimeCost: Int?

    /// Creates a header. Argon2id fields are `nil` for version-1 documents.
    public init(
        formatVersion: Int,
        kdfSalt: Data,
        kdfIterations: Int,
        wrappedDataKey: SealedPayload,
        deviceWrappedDataKey: SealedPayload?,
        headHash: Data,
        kdfAlgorithm: String,
        kdfMemoryKiB: Int? = nil,
        kdfParallelism: Int? = nil,
        kdfTimeCost: Int? = nil
    ) {
        self.formatVersion = formatVersion
        self.kdfSalt = kdfSalt
        self.kdfIterations = kdfIterations
        self.wrappedDataKey = wrappedDataKey
        self.deviceWrappedDataKey = deviceWrappedDataKey
        self.headHash = headHash
        self.kdfAlgorithm = kdfAlgorithm
        self.kdfMemoryKiB = kdfMemoryKiB
        self.kdfParallelism = kdfParallelism
        self.kdfTimeCost = kdfTimeCost
    }

    private enum CodingKeys: String, CodingKey {
        case formatVersion, kdfSalt, kdfIterations, wrappedDataKey
        case deviceWrappedDataKey, headHash
        case kdfAlgorithm, kdfMemoryKiB, kdfParallelism, kdfTimeCost
    }

    /// Codable conformance so version-1 documents keep decoding forever:
    /// absent KDF fields decode to `nil` and the algorithm is inferred (D-04).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        formatVersion = try c.decode(Int.self, forKey: .formatVersion)
        kdfSalt = try c.decode(Data.self, forKey: .kdfSalt)
        kdfIterations = try c.decode(Int.self, forKey: .kdfIterations)
        wrappedDataKey = try c.decode(SealedPayload.self, forKey: .wrappedDataKey)
        deviceWrappedDataKey = try c.decodeIfPresent(SealedPayload.self, forKey: .deviceWrappedDataKey)
        headHash = try c.decode(Data.self, forKey: .headHash)
        // Version-1 documents predate the explicit field; the only v1 KDF is PBKDF2.
        kdfAlgorithm = try c.decodeIfPresent(String.self, forKey: .kdfAlgorithm)
            ?? (formatVersion < 2 ? VaultKDF.pbkdf2 : "")
        kdfMemoryKiB = try c.decodeIfPresent(Int.self, forKey: .kdfMemoryKiB)
        kdfParallelism = try c.decodeIfPresent(Int.self, forKey: .kdfParallelism)
        kdfTimeCost = try c.decodeIfPresent(Int.self, forKey: .kdfTimeCost)
    }

    /// Encodes every field; absent optionals are omitted, keeping the JSON
    /// wire format stable for older readers (frozen format).
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(formatVersion, forKey: .formatVersion)
        try c.encode(kdfSalt, forKey: .kdfSalt)
        try c.encode(kdfIterations, forKey: .kdfIterations)
        try c.encode(wrappedDataKey, forKey: .wrappedDataKey)
        try c.encodeIfPresent(deviceWrappedDataKey, forKey: .deviceWrappedDataKey)
        try c.encode(headHash, forKey: .headHash)
        try c.encode(kdfAlgorithm, forKey: .kdfAlgorithm)
        try c.encodeIfPresent(kdfMemoryKiB, forKey: .kdfMemoryKiB)
        try c.encodeIfPresent(kdfParallelism, forKey: .kdfParallelism)
        try c.encodeIfPresent(kdfTimeCost, forKey: .kdfTimeCost)
    }
}

/// The serializable vault: header + append-only log. This is what a Secure
/// Mirror exports and what `.kdbx` conversion reads from.
public struct VaultDocument: Sendable, Equatable, Codable {
    /// Key-wrapping parameters and wrapped data keys.
    public var header: VaultHeader
    /// Tamper-evident record history.
    public var log: AppendOnlyLog
}
