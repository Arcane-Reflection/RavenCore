import CryptoKit
import Foundation

/// One tamper-evident entry in the vault's append-only history.
/// `archivedAt` is deliberately excluded from `hash`: archiving is a metadata
/// change and must not invalidate the chain.
public struct VaultLogEntry: Sendable, Equatable, Codable, Identifiable {
    /// Record identifier.
    public let id: UUID
    /// When the record entered the log (part of the hash input).
    public let createdAt: Date
    /// Encrypted record payload (sealed by the vault layer).
    public let payload: Data
    /// Writable within the module: `AppendOnlyLog.compact()` rebuilds linkage.
    public internal(set) var previousHash: Data
    /// SHA-256 linkage to the previous entry (module-writable: compaction
    /// rebuilds linkage).
    public internal(set) var hash: Data
    /// Soft-delete timestamp — deliberately excluded from `hash`.
    public internal(set) var archivedAt: Date?

    /// Soft-delete state.
    public var isArchived: Bool { archivedAt != nil }

    init(id: UUID = UUID(), createdAt: Date, payload: Data, previousHash: Data, hash: Data, archivedAt: Date? = nil) {
        self.id = id
        self.createdAt = createdAt
        self.payload = payload
        self.previousHash = previousHash
        self.hash = hash
        self.archivedAt = archivedAt
    }
}

/// Chain-hashed, append-only record history.
///
/// "A stone tablet with a chisel": records cannot be deleted, only archived,
/// and archiving is reversible until the owner explicitly compacts — which
/// rebuilds the chain over the surviving entries (an owner-authoritative
/// rewrite, like a git rebase).
public struct AppendOnlyLog: Sendable, Equatable, Codable {
    /// Domain-separated label hashed into the genesis hash.
    public static let genesisLabel = "ravenvault-genesis-v1"

    /// The history, in append order (mutation confined to the module).
    public internal(set) var entries: [VaultLogEntry]
    /// Hash of the last entry (genesis hash when empty).
    public internal(set) var headHash: Data

    /// Creates an empty log rooted at the genesis hash.
    public init() {
        entries = []
        headHash = Self.genesisHash
    }

    static var genesisHash: Data {
        Data(SHA256.hash(data: Data(Self.genesisLabel.utf8)))
    }

    /// Appends `payload` and returns the new entry.
    @discardableResult
    public mutating func append(payload: Data, at date: Date = Date()) -> VaultLogEntry {
        let entry = VaultLogEntry(
            createdAt: date,
            payload: payload,
            previousHash: headHash,
            hash: Self.entryHash(previousHash: headHash, createdAt: date, payload: payload)
        )
        entries.append(entry)
        headHash = entry.hash
        return entry
    }

    /// Soft-delete: marks the entry archived. Reversible via compaction only.
    @discardableResult
    public mutating func archive(id: UUID, at date: Date = Date()) -> Bool {
        guard let index = entries.firstIndex(where: { $0.id == id }), !entries[index].isArchived else {
            return false
        }
        entries[index].archivedAt = date
        return true
    }

    /// Permanently removes archived entries and rebuilds chain linkage over
    /// the survivors. Returns the number of entries removed.
    @discardableResult
    public mutating func compact() -> Int {
        let kept = entries.filter { !$0.isArchived }
        let removed = entries.count - kept.count
        guard removed > 0 else { return 0 }

        var previous = Self.genesisHash
        entries = kept.map { entry in
            var rebuilt = entry
            rebuilt.previousHash = previous
            rebuilt.hash = Self.entryHash(previousHash: previous, createdAt: entry.createdAt, payload: entry.payload)
            previous = rebuilt.hash
            return rebuilt
        }
        headHash = previous
        return removed
    }

    /// Recomputes the full chain from genesis and checks linkage + head.
    public func verify() -> Bool {
        var previous = Self.genesisHash
        for entry in entries {
            guard entry.previousHash == previous else { return false }
            guard entry.hash == Self.entryHash(previousHash: entry.previousHash, createdAt: entry.createdAt, payload: entry.payload) else {
                return false
            }
            previous = entry.hash
        }
        return headHash == previous
    }

    static func entryHash(previousHash: Data, createdAt: Date, payload: Data) -> Data {
        var input = Data()
        input.append(previousHash)
        withUnsafeBytes(of: UInt64(bitPattern: Int64(createdAt.timeIntervalSince1970.rounded())).bigEndian) {
            input.append(contentsOf: $0)
        }
        input.append(payload)
        return Data(SHA256.hash(data: input))
    }
}
