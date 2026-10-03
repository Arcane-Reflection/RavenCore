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
    /// Emergency Card (07-CONTEXT D-16/D-17): a user-editable free-form
    /// record (emergency contacts, medical info, exit instructions) that is
    /// HARD-excluded from every export/search/AutoFill surface via the app
    /// layer's single `EmergencyCardPolicy.isEmergencyCard` predicate.
    /// Additive enum case following the passkey precedent: the raw-value
    /// Codable synthesizes fine and pre-card envelopes (no such raw value
    /// ever written) decode unchanged — `formatVersion` is NOT bumped.
    case emergencyCard
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
    /// Account URL, if any (04-CONTEXT D-01 — the Phase 5 CSV/kdbx mapping
    /// and Phase 6 AutoFill anchor).
    public var url: String?
    /// FIDO2/WebAuthn credential, if any (06-CONTEXT D-09). The Phase 2
    /// `PasskeyCredential` (KPEX_PASSKEY_* attribute set pinned by the kxc
    /// corpus) is reused verbatim. Additive optional extension following the
    /// attachments precedent: synthesized decoding tolerates absence (a
    /// pre-passkey envelope decodes with `passkey == nil` forever) and
    /// encoding omits the key when nil, so the wire format stays stable and
    /// `formatVersion` is unchanged.
    public var passkey: PasskeyCredential?

    /// Creates a payload; omitted fields default to empty/nil.
    public init(
        title: String,
        username: String = "",
        password: String = "",
        notes: String = "",
        totpSecret: String? = nil,
        seedPhrase: [String]? = nil,
        url: String? = nil,
        passkey: PasskeyCredential? = nil
    ) {
        self.title = title
        self.username = username
        self.password = password
        self.notes = notes
        self.totpSecret = totpSecret
        self.seedPhrase = seedPhrase
        self.url = url
        self.passkey = passkey
    }
}

/// A folder in the vault's organizational tree (04-CONTEXT D-01/D-02).
///
/// Folder metadata lives on the document, not in the append-only log: it is
/// organizational structure (like kdbx groups), not record history. The data
/// model supports nesting via `parentID`; the v1 UI renders it flat. Folders
/// travel with the vault file — they are vault data, never app-side state.
public struct Folder: Sendable, Equatable, Codable, Identifiable {
    /// Folder identifier (referenced by `RecordEnvelope.folderID`).
    public var id: UUID
    /// Display name (unique among siblings).
    public var name: String
    /// Parent folder, or nil for a root folder. Nesting-capable for the
    /// Phase 5 kdbx group mapping; v1 UI renders flat.
    public var parentID: UUID?

    public init(id: UUID = UUID(), name: String, parentID: UUID? = nil) {
        self.id = id
        self.name = name
        self.parentID = parentID
    }
}

/// A file attachment carried inside a record envelope (05-CONTEXT D-04).
///
/// Bytes are inline: attachments travel with the vault file itself, never as
/// app-side sidecars ("vault data travels with the file" hard constraint).
/// Versioned content — the attachment list rides the envelope, so history
/// versions carry the attachments they had at that version (kdbx parity).
/// One hard per-attachment cap bounds memory: oversized input fails loudly
/// at the interop boundary, never truncates (T-05-03).
public struct RecordAttachment: Sendable, Equatable, Codable {
    /// Attachment identity (the share/export paths address attachments by id).
    public var id: UUID
    /// File name as displayed.
    public var name: String
    /// MIME-style content type, when known (kdbx sources carry none).
    public var contentType: String?
    /// Raw attachment bytes.
    public var data: Data

    /// Creates an attachment.
    public init(id: UUID, name: String, contentType: String?, data: Data) {
        self.id = id
        self.name = name
        self.contentType = contentType
        self.data = data
    }
}

/// What actually gets encrypted into a log entry's payload.
struct RecordEnvelope: Codable, Sendable, Equatable {
    var type: RecordType
    var level: SecurityLevel
    var record: RecordPayload
    /// Free-form organizational tags (04-CONTEXT D-02 — no separate tag
    /// entity in v1; the tag list is aggregated from records).
    var tags: [String]? = nil
    /// Containing folder, if any (references `VaultDocument.folders`).
    var folderID: UUID? = nil
    /// File attachments (05-CONTEXT D-04). Additive optional extension:
    /// absent (nil) in envelopes written before the extension; omitted when
    /// nil so the v2 wire format stays stable for pre-extension readers.
    var attachments: [RecordAttachment]? = nil

    private enum CodingKeys: String, CodingKey {
        case type, level, record, tags, folderID, attachments
    }

    /// Explicit Codable so pre-extension envelopes (no `attachments` key)
    /// decode forever: absent decodes to nil (D-04 fixture-first discipline).
    init(
        type: RecordType,
        level: SecurityLevel,
        record: RecordPayload,
        tags: [String]? = nil,
        folderID: UUID? = nil,
        attachments: [RecordAttachment]? = nil
    ) {
        self.type = type
        self.level = level
        self.record = record
        self.tags = tags
        self.folderID = folderID
        self.attachments = attachments
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        type = try c.decode(RecordType.self, forKey: .type)
        level = try c.decode(SecurityLevel.self, forKey: .level)
        record = try c.decode(RecordPayload.self, forKey: .record)
        tags = try c.decodeIfPresent([String].self, forKey: .tags)
        folderID = try c.decodeIfPresent(UUID.self, forKey: .folderID)
        attachments = try c.decodeIfPresent([RecordAttachment].self, forKey: .attachments)
    }

    /// Encodes every field; absent optionals are omitted, keeping the JSON
    /// wire format stable for older readers (frozen format).
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(type, forKey: .type)
        try c.encode(level, forKey: .level)
        try c.encode(record, forKey: .record)
        try c.encodeIfPresent(tags, forKey: .tags)
        try c.encodeIfPresent(folderID, forKey: .folderID)
        try c.encodeIfPresent(attachments, forKey: .attachments)
    }
}

/// A decrypted record surfaced to the app layer (deduplicated: one instance
/// per record id — the newest version wins, 04-CONTEXT D-03).
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
    /// Free-form organizational tags, if any (04-CONTEXT D-02).
    public let tags: [String]?
    /// Containing folder, if any (references `VaultDocument.folders`).
    public let folderID: UUID?
    /// File attachments of the newest version, if any (05-CONTEXT D-04).
    /// Absent (nil) for records whose versions predate the extension.
    public let attachments: [RecordAttachment]?
    /// Soft-delete state (reversible until compaction).
    public let isArchived: Bool

    public init(
        id: UUID,
        createdAt: Date,
        type: RecordType,
        level: SecurityLevel,
        payload: RecordPayload,
        tags: [String]? = nil,
        folderID: UUID? = nil,
        attachments: [RecordAttachment]? = nil,
        isArchived: Bool
    ) {
        self.id = id
        self.createdAt = createdAt
        self.type = type
        self.level = level
        self.payload = payload
        self.tags = tags
        self.folderID = folderID
        self.attachments = attachments
        self.isArchived = isArchived
    }
}

/// One historical version of a record — the read-only full-history view
/// behind `VaultService.allVersions()` (05-01: the kdbx export replay needs
/// every version, not just the deduplicated newest).
public struct RecordVersion: Sendable, Equatable {
    /// Decrypted content of this version.
    public let payload: RecordPayload
    /// Free-form organizational tags, if any.
    public let tags: [String]?
    /// Containing folder, if any.
    public let folderID: UUID?
    /// File attachments of this version, if any.
    public let attachments: [RecordAttachment]?
    /// Version timestamp (the log entry's `createdAt`).
    public let at: Date

    /// Creates a version view; used by `VaultService.allVersions()`.
    public init(
        payload: RecordPayload,
        tags: [String]?,
        folderID: UUID?,
        attachments: [RecordAttachment]?,
        at: Date
    ) {
        self.payload = payload
        self.tags = tags
        self.folderID = folderID
        self.attachments = attachments
        self.at = at
    }
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
    /// Organizational folder tree (04-CONTEXT D-01). Document-level metadata
    /// outside the record chain — like the header. Absent (nil) in vaults
    /// written before the extension; omitted when empty so the v2 wire format
    /// stays stable for pre-extension readers.
    public var folders: [Folder]? = nil
}
