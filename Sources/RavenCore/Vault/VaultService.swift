import CryptoKit
import Foundation

/// Errors thrown by the vault engine. All `Equatable` for exact-case test
/// assertions; failures never distinguish which credential half was wrong.
public enum VaultError: Error, Equatable {
    /// GCM authentication failed — wrong passphrase or tampered bytes; never
    /// distinguishes which half failed.
    case wrongPassphrase
    /// The data key is not in memory; unlock before performing this operation.
    case locked
    /// The document failed to decode or failed pre-auth integrity guards.
    case corruptDocument
    /// No record with the requested identifier exists in the log.
    case recordNotFound
    // Folder organization (04-CONTEXT D-02).
    /// No folder with the requested identifier exists.
    case folderNotFound
    /// The folder still contains records (or subfolders) and cannot be removed.
    case folderNotEmpty
    /// The folder name violates the naming rules (empty or reserved).
    case invalidFolderName
    /// A folder with this name already exists.
    case duplicateFolderName
}

/// The vault engine: create, unlock, append records to the chain, archive,
/// compact, and serialize. Holds the data key in memory only while unlocked.
public final class VaultService {

    /// Current format. Version 2 switched the default KDF to Argon2id
    /// (parameters in header); version-1 PBKDF2 documents stay unlockable.
    public static let formatVersion = 2
    /// Legacy default iteration count for version-1 creation/fixtures.
    public static let defaultIterations = KeyDerivation.recommendedIterations

    private var document: VaultDocument
    /// Authoritative key bytes. Held as `Data` (not `SymmetricKey`) so the
    /// scrub-on-lock is possible — `SymmetricKey` offers no in-place clearing
    /// (CONCERNS.md tech debt, fixed per ARCH-04/D-08). Crypto call sites
    /// materialize a transient `SymmetricKey` per operation and discard it;
    /// `dataKeyBytes` itself is zeroed on `lock()` and `deinit`.
    var dataKeyBytes: Data?
#if DEBUG
    /// Test hook: number of key bytes scrubbed by the most recent lock (0
    /// when nothing was held). Exists so the zeroization test can observe
    /// the scrub without keeping secret bytes alive in a snapshot.
    var lastScrubbedKeyByteCount: Int = 0
#endif

    /// `true` while the data key is held in memory.
    public var isUnlocked: Bool { dataKeyBytes != nil }
    /// Hash of the newest log entry.
    public var headHash: Data { document.header.headHash }
    /// `true` when a device wrap (the Secure Enclave half) is attached to the
    /// header. Independent of the passphrase wrap — either wrap alone opens
    /// the vault, and attaching never removes the passphrase half.
    public var hasDeviceWrap: Bool { document.header.deviceWrappedDataKey != nil }

    // MARK: - Lifecycle

    /// Creates a new vault with a fresh random 32-byte data key wrapped under
    /// an Argon2id-derived KEK (D-01 defaults; parameters stored per-vault).
    public static func create(passphrase: String) throws -> VaultService {
        try createWithKDF(
            passphrase: passphrase,
            kdfAlgorithm: VaultKDF.argon2id
        )
    }

    /// Version-1 creation path: PBKDF2-HMAC-SHA256. Kept for fixtures and
    /// legacy-compat testing — new vaults must use `create(passphrase:)`.
    public static func createLegacyPBKDF2(
        passphrase: String,
        iterations: Int = VaultService.defaultIterations
    ) throws -> VaultService {
        try createWithKDF(passphrase: passphrase, kdfAlgorithm: VaultKDF.pbkdf2, pbkdf2Iterations: iterations)
    }

    private static func createWithKDF(
        passphrase: String,
        kdfAlgorithm: String,
        pbkdf2Iterations: Int = KeyDerivation.recommendedIterations
    ) throws -> VaultService {
        guard !passphrase.isEmpty else { throw VaultError.wrongPassphrase }
        let salt = SecureRandom.bytes(count: 16)
        let dataKeyBytes = SecureRandom.bytes(count: 32)
        let dataKey = SymmetricKey(data: dataKeyBytes) // transient: sealed immediately below
        let header: VaultHeader
        switch kdfAlgorithm {
        case VaultKDF.argon2id:
            let kekData = try KeyDerivation.argon2id(
                password: Data(passphrase.utf8),
                salt: salt,
                memoryKiB: KeyDerivation.argon2MemoryKiB,
                timeCost: KeyDerivation.argon2TimeCost,
                parallelism: KeyDerivation.argon2Parallelism
            )
            let wrapped = try AESGCMCipher.encrypt(dataKeyBytes, key: SymmetricKey(data: kekData))
            header = VaultHeader(
                formatVersion: formatVersion,
                kdfSalt: salt,
                kdfIterations: pbkdf2Iterations,
                wrappedDataKey: wrapped,
                deviceWrappedDataKey: nil,
                headHash: Data(),
                kdfAlgorithm: VaultKDF.argon2id,
                kdfMemoryKiB: KeyDerivation.argon2MemoryKiB,
                kdfParallelism: KeyDerivation.argon2Parallelism,
                kdfTimeCost: KeyDerivation.argon2TimeCost
            )
        case VaultKDF.pbkdf2:
            let kekData = try KeyDerivation.pbkdf2SHA256(password: Data(passphrase.utf8), salt: salt, iterations: pbkdf2Iterations)
            let wrapped = try AESGCMCipher.encrypt(dataKeyBytes, key: SymmetricKey(data: kekData))
            header = VaultHeader(
                formatVersion: 1,
                kdfSalt: salt,
                kdfIterations: pbkdf2Iterations,
                wrappedDataKey: wrapped,
                deviceWrappedDataKey: nil,
                headHash: Data(),
                kdfAlgorithm: VaultKDF.pbkdf2
            )
        default:
            throw VaultError.corruptDocument
        }

        var log = AppendOnlyLog()
        var finalHeader = header
        finalHeader.headHash = log.headHash
        return VaultService(document: VaultDocument(header: finalHeader, log: log), keyBytes: dataKeyBytes)
    }

    /// Derives the KEK for a header's KDF (v1/v2 dispatch).
    ///
    /// Boundary mapping (FW-03): the header is untrusted input until the GCM
    /// check authenticates it, so parameter guards never surface as
    /// `KeyDerivationError` — callers exhaustively switching on `VaultError`
    /// see `corruptDocument` for tampered/out-of-bounds KDF parameters.
    private static func deriveKEK(passphrase: String, header: VaultHeader) throws -> SymmetricKey {
        let password = Data(passphrase.utf8)
        switch header.kdfAlgorithm {
        case VaultKDF.argon2id:
            guard let memoryKiB = header.kdfMemoryKiB,
                  let parallelism = header.kdfParallelism,
                  let timeCost = header.kdfTimeCost else {
                throw VaultError.corruptDocument
            }
            // FI-08: header fields are untrusted until the GCM check
            // authenticates them. No app-written vault can exceed the D-01
            // defaults (m = 64 MiB, t = 3, p = 2 — rewrap writes the same),
            // and future presets (D-02) keep huge headroom. The caps are the
            // shared hostile-header vocabulary (261003-mk7 second pass —
            // identical to the kdbx and mirror paths), keeping a tampered
            // header from triggering a jetsam-scale Argon2 allocation on iOS
            // instead of a clean typed failure.
            guard memoryKiB <= KeyDerivation.hostileMaxMemoryKiB,
                  timeCost <= KeyDerivation.hostileMaxTimeCost,
                  parallelism <= KeyDerivation.hostileMaxParallelism else {
                throw VaultError.corruptDocument
            }
            do {
                return SymmetricKey(data: try KeyDerivation.argon2id(
                    password: password, salt: header.kdfSalt,
                    memoryKiB: memoryKiB, timeCost: timeCost, parallelism: parallelism
                ))
            } catch {
                throw VaultError.corruptDocument
            }
        case VaultKDF.pbkdf2:
            // Caller-side ceiling: pbkdf2SHA256 is the frozen version-1 path
            // (its guard is deliberately minimal per I-01's freeze rule), but
            // a tampered header above UInt32.max must fail typed rather than
            // silently truncate at the cast. Below-range values are mapped by
            // the catch below.
            guard header.kdfIterations <= Int(UInt32.max) else {
                throw VaultError.corruptDocument
            }
            do {
                return SymmetricKey(data: try KeyDerivation.pbkdf2SHA256(
                    password: password, salt: header.kdfSalt, iterations: header.kdfIterations
                ))
            } catch {
                // e.g. a tampered header with kdfIterations = 0 — the frozen
                // version-1 path rejects it; here it becomes the module error.
                throw VaultError.corruptDocument
            }
        default:
            // Unknown algorithm: refuse rather than guess (format gate).
            throw VaultError.corruptDocument
        }
    }

    /// Loads and unlocks a serialized vault document (any formatVersion).
    public static func unlock(serializedDocument: Data, passphrase: String) throws -> VaultService {
        guard let document = try? JSONDecoder().decode(VaultDocument.self, from: serializedDocument) else {
            throw VaultError.corruptDocument
        }
        let kek = try deriveKEK(passphrase: passphrase, header: document.header)
        let keyData: Data
        do {
            keyData = try AESGCMCipher.decrypt(document.header.wrappedDataKey, key: kek)
        } catch {
            throw VaultError.wrongPassphrase
        }
        let service = VaultService(document: document, keyBytes: keyData)
        // D-04: capture the legacy passphrase so the next save can upgrade the
        // header to Argon2id. Consumed (and scrubbed) by upgradeIfNeeded.
        if document.header.formatVersion < VaultService.formatVersion,
           document.header.kdfAlgorithm == VaultKDF.pbkdf2 {
            service.legacyPassphrase = Data(passphrase.utf8)
        }
        return service
    }

    init(document: VaultDocument, keyBytes: Data?) {
        self.document = document
        self.dataKeyBytes = keyBytes
    }

    /// Transient `SymmetricKey` for a single crypto call. The materialized
    /// key is a copy — use and discard immediately; the authoritative bytes
    /// in `dataKeyBytes` are the scrub target (transient: per-call copy).
    private func materializedKey() throws -> SymmetricKey {
        guard let dataKeyBytes else { throw VaultError.locked }
        return SymmetricKey(data: dataKeyBytes)
    }

    /// Clears the data key from memory (D-08): bytes are scrubbed in place
    /// with `SecureMemory.zero` before the reference is dropped, so a freed
    /// buffer never carries key material. `deinit` repeats the scrub.
    public func lock() {
#if DEBUG
        lastScrubbedKeyByteCount = 0 // reset per attempt so a no-op lock is observable
#endif
        if dataKeyBytes != nil {
#if DEBUG
            lastScrubbedKeyByteCount = dataKeyBytes!.count
#endif
            SecureMemory.zero(&dataKeyBytes!)
            dataKeyBytes = nil
        }
        if legacyPassphrase != nil {
            SecureMemory.zero(&legacyPassphrase!)
            legacyPassphrase = nil
        }
    }

    deinit {
        if dataKeyBytes != nil {
            SecureMemory.zero(&dataKeyBytes!)
        }
        if legacyPassphrase != nil {
            SecureMemory.zero(&legacyPassphrase!)
        }
    }

    // MARK: - Records

    @discardableResult
    /// Appends a record (payload encrypted under the data key) to the log.
    /// - Returns: the new record's identifier.
    public func add(
        _ type: RecordType,
        level: SecurityLevel,
        payload: RecordPayload,
        tags: [String]? = nil,
        folderID: UUID? = nil,
        attachments: [RecordAttachment]? = nil,
        at date: Date = Date()
    ) throws -> UUID {
        let envelope = RecordEnvelope(
            type: type, level: level, record: payload, tags: tags, folderID: folderID,
            attachments: attachments)
        return try appendEnvelope(envelope, id: UUID(), at: date)
    }

    /// Supersedes an existing record with new content under the SAME id
    /// (04-CONTEXT D-03): the prior version stays in the log (append-only
    /// history), `records()`/`activeRecords()` surface only the newest
    /// version per id. The new version is active (not archived).
    public func update(
        id: UUID,
        type: RecordType,
        level: SecurityLevel,
        payload: RecordPayload,
        tags: [String]? = nil,
        folderID: UUID? = nil,
        attachments: [RecordAttachment]? = nil,
        at date: Date = Date()
    ) throws {
        guard try containsRecord(id: id) else { throw VaultError.recordNotFound }
        let envelope = RecordEnvelope(
            type: type, level: level, record: payload, tags: tags, folderID: folderID,
            attachments: attachments)
        _ = try appendEnvelope(envelope, id: id, at: date)
    }

    /// Reverses an archive: every version of `id` becomes active again.
    public func unarchive(id: UUID) throws {
        guard dataKeyBytes != nil else { throw VaultError.locked }
        guard document.log.unarchive(id: id) else { throw VaultError.recordNotFound }
    }

    /// The organizational folder tree (empty when the vault predates folders).
    public func folders() -> [Folder] {
        document.folders ?? []
    }

    /// Creates a folder in the organizational tree (04-CONTEXT D-02).
    /// - Returns: the new folder's identifier.
    @discardableResult
    public func addFolder(name: String, parentID: UUID? = nil) throws -> UUID {
        var folders = document.folders ?? []
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty else { throw VaultError.invalidFolderName }
        if let parentID {
            guard folders.contains(where: { $0.id == parentID }) else {
                throw VaultError.folderNotFound
            }
        }
        guard !folders.contains(where: { $0.parentID == parentID && $0.name == cleanName }) else {
            throw VaultError.duplicateFolderName
        }
        let folder = Folder(id: UUID(), name: cleanName, parentID: parentID)
        folders.append(folder)
        document.folders = folders
        return folder.id
    }

    /// Renames a folder; the name must stay unique among its siblings.
    public func renameFolder(id: UUID, to name: String) throws {
        var folders = document.folders ?? []
        guard let index = folders.firstIndex(where: { $0.id == id }) else {
            throw VaultError.folderNotFound
        }
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty else { throw VaultError.invalidFolderName }
        let parentID = folders[index].parentID
        guard !folders.contains(where: { $0.id != id && $0.parentID == parentID && $0.name == cleanName }) else {
            throw VaultError.duplicateFolderName
        }
        folders[index].name = cleanName
        document.folders = folders
    }

    /// Deletes a folder — only when nothing references it: no record version
    /// (active or archived) may carry its id, and it may have no child
    /// folders. Organizational metadata only; record data is never touched.
    public func deleteFolder(id: UUID) throws {
        guard (document.folders ?? []).contains(where: { $0.id == id }) else {
            throw VaultError.folderNotFound
        }
        if (document.folders ?? []).contains(where: { $0.parentID == id }) {
            throw VaultError.folderNotEmpty
        }
        // Reference check runs on the deduplicated view (what the user sees):
        // superseded versions may still carry a stale folderID, which is
        // harmless — the UI falls back to "No Folder" for missing folders.
        if try records().contains(where: { $0.folderID == id }) {
            throw VaultError.folderNotEmpty
        }
        document.folders?.removeAll { $0.id == id }
        if document.folders?.isEmpty == true { document.folders = nil }
    }

    /// Decrypts and returns the full history (including archived records),
    /// deduplicated per record id: the newest `createdAt` version wins —
    /// equal timestamps break to the last-appended log entry (the canonical
    /// tie rule, 05 review WR-04) — and output order follows each id's first
    /// appearance (04-CONTEXT D-03).
    public func records() throws -> [DecryptedRecord] {
        var byId: [UUID: DecryptedRecord] = [:]
        var order: [UUID] = []
        for record in try decryptAllRecords() {
            if let existing = byId[record.id] {
                if record.createdAt >= existing.createdAt {
                    byId[record.id] = record
                }
            } else {
                byId[record.id] = record
                order.append(record.id)
            }
        }
        return order.compactMap { byId[$0] }
    }

    /// Decrypts and returns the non-archived records (same dedupe as `records()`).
    public func activeRecords() throws -> [DecryptedRecord] {
        try records().filter { !$0.isArchived }
    }

    /// Read-only full-history view (05-01): every version per record id,
    /// oldest → newest, EXCLUDING the newest — the newest version rides
    /// `records()`, so export replays history + current without duplication.
    /// Single-version records map to an empty array.
    ///
    /// Newest-version selection uses the SAME rule as `records()` —
    /// last-appended wins on equal timestamps — so the two views can never
    /// disagree: the dropped entry is exactly the version `records()`
    /// surfaces, and every other version appears once (05 review WR-04).
    public func allVersions() throws -> [UUID: [RecordVersion]] {
        let dataKey = try materializedKey() // transient: scope-local copy
        let decoder = JSONDecoder()
        var byId: [UUID: [(at: Date, version: RecordVersion)]] = [:]
        for entry in document.log.entries {
            let sealed = try decoder.decode(SealedPayload.self, from: entry.payload)
            let envelopeData = try AESGCMCipher.decrypt(sealed, key: dataKey)
            let envelope = try decoder.decode(RecordEnvelope.self, from: envelopeData)
            let version = RecordVersion(
                payload: envelope.record,
                tags: envelope.tags,
                folderID: envelope.folderID,
                attachments: envelope.attachments,
                at: entry.createdAt)
            byId[entry.id, default: []].append((entry.createdAt, version))
        }
        var result: [UUID: [RecordVersion]] = [:]
        for (id, versions) in byId {
            // The log is append-ordered per id; sort defensively with an
            // index tie-break so equal timestamps resolve deterministically —
            // the last-appended entry sorts last, matching `records()`'s
            // `>=` newest-wins rule (WR-04). A bare date sort leaves the
            // tie order unspecified and could drop a different entry than
            // `records()` keeps (duplicating one version, losing another).
            let ordered = versions.enumerated().sorted { lhs, rhs in
                lhs.element.at < rhs.element.at
                    || (lhs.element.at == rhs.element.at && lhs.offset < rhs.offset)
            }.map(\.element.version)
            result[id] = Array(ordered.dropLast())
        }
        return result
    }

    /// Soft-deletes a record (history preserved, reversible until compaction).
    public func archive(id: UUID) throws {
        guard document.log.archive(id: id) else { throw VaultError.recordNotFound }
    }

    /// Owner-authoritative rewrite: permanently drops archived entries.
    @discardableResult
    public func compact() throws -> Int {
        let removed = document.log.compact()
        document.header.headHash = document.log.headHash
        return removed
    }

    /// `true` when the chain verifies and the header head hash is current.
    public func verifyChain() -> Bool {
        document.log.verify() && document.header.headHash == document.log.headHash
    }

    // MARK: - Record internals

    /// Encrypts and appends an envelope under an explicit record id.
    private func appendEnvelope(_ envelope: RecordEnvelope, id: UUID, at date: Date) throws -> UUID {
        guard dataKeyBytes != nil else { throw VaultError.locked }
        let sealed = try AESGCMCipher.encrypt(try JSONEncoder().encode(envelope), key: try materializedKey()) // transient: per-call copy
        let entry = document.log.append(payload: try JSONEncoder().encode(sealed), at: date, id: id)
        document.header.headHash = document.log.headHash
        return entry.id
    }

    private func containsRecord(id: UUID) throws -> Bool {
        try decryptAllRecords().contains { $0.id == id }
    }

    /// Decrypts every log entry to its envelope snapshot (id/createdAt/
    /// archived state included — the raw per-entry view, pre-dedupe).
    private func decryptAllRecords() throws -> [DecryptedRecord] {
        let dataKey = try materializedKey() // transient: scope-local copy
        let decoder = JSONDecoder()
        return try document.log.entries.map { entry in
            let sealed = try decoder.decode(SealedPayload.self, from: entry.payload)
            let envelopeData = try AESGCMCipher.decrypt(sealed, key: dataKey)
            let envelope = try decoder.decode(RecordEnvelope.self, from: envelopeData)
            return DecryptedRecord(
                id: entry.id,
                createdAt: entry.createdAt,
                type: envelope.type,
                level: envelope.level,
                payload: envelope.record,
                tags: envelope.tags,
                folderID: envelope.folderID,
                attachments: envelope.attachments,
                isArchived: entry.isArchived
            )
        }
    }

    // MARK: - KDF migration (D-03/D-04)

    /// Transient passphrase of a legacy (v1) vault, captured at unlock and
    /// consumed by the save-time upgrade. Never persisted; held as Data so the
    /// upgrade can re-derive the Argon2id KEK without keeping a String alive.
    private var legacyPassphrase: Data?

    /// Re-wraps the data key under a fresh Argon2id KEK (new salt, D-01
    /// defaults) and marks the header formatVersion 2. Requires unlocked
    /// state; the log is untouched — this is a header-only operation.
    public func rewrap(passphrase: String) throws {
        guard let dataKeyBytes else { throw VaultError.locked }
        try rewrapHeader(dataKeyBytes: dataKeyBytes, kekPassword: Data(passphrase.utf8))
    }

    /// Upgrades a legacy (v1) header to Argon2id when serializing an unlocked
    /// vault (D-04: save = upgrade), using the passphrase captured at unlock.
    /// Locked vaults serialize unchanged — there is neither a data key nor a
    /// captured passphrase to re-wrap with.
    private func upgradeIfNeeded() throws {
        guard isUnlocked,
              document.header.formatVersion < VaultService.formatVersion,
              let passphrase = legacyPassphrase, !passphrase.isEmpty else { return }
        try rewrapHeader(dataKeyBytes: dataKeyBytes!, kekPassword: passphrase)
        SecureMemory.zero(&legacyPassphrase!)
        legacyPassphrase = nil
    }

    private func rewrapHeader(dataKeyBytes: Data, kekPassword: Data) throws {
        guard !kekPassword.isEmpty else { throw VaultError.wrongPassphrase }
        let salt = SecureRandom.bytes(count: 16)
        let kekData = try KeyDerivation.argon2id(
            password: kekPassword,
            salt: salt,
            memoryKiB: KeyDerivation.argon2MemoryKiB,
            timeCost: KeyDerivation.argon2TimeCost,
            parallelism: KeyDerivation.argon2Parallelism
        )
        document.header.wrappedDataKey = try AESGCMCipher.encrypt(dataKeyBytes, key: SymmetricKey(data: kekData))
        document.header.kdfSalt = salt
        document.header.kdfIterations = KeyDerivation.recommendedIterations
        document.header.kdfAlgorithm = VaultKDF.argon2id
        document.header.kdfMemoryKiB = KeyDerivation.argon2MemoryKiB
        document.header.kdfParallelism = KeyDerivation.argon2Parallelism
        document.header.kdfTimeCost = KeyDerivation.argon2TimeCost
        document.header.formatVersion = VaultService.formatVersion
    }

    // MARK: - Persistence

    /// Serializes the document (upgrading a legacy header first, D-04).
    public func serializedDocument() throws -> Data {
        try upgradeIfNeeded()
        document.header.headHash = document.log.headHash
        return try JSONEncoder().encode(document)
    }

    // MARK: - Dual-wrap (device path)

    /// Wraps the data key under a second provider (Secure Enclave on device)
    /// so the vault can be opened without the passphrase after device migration.
    /// The passphrase wrap is never touched — the device wrap is strictly
    /// additive (CONTEXT D-06; "either wrap alone opens the vault").
    public func attachDeviceWrap(using provider: WrappingKeyProvider) throws {
        let key = try materializedKey() // transient: sealed immediately by the provider
        document.header.deviceWrappedDataKey = try provider.wrap(key)
    }

    /// Unlocks using the device wrap (e.g. after Secure Enclave biometric auth).
    public static func unlockWithDeviceWrap(serializedDocument: Data, provider: WrappingKeyProvider) throws -> VaultService {
        guard let document = try? JSONDecoder().decode(VaultDocument.self, from: serializedDocument),
              let deviceWrapped = document.header.deviceWrappedDataKey else {
            throw VaultError.corruptDocument
        }
        let unwrapped: SymmetricKey
        do {
            unwrapped = try provider.unwrap(deviceWrapped) // transient: converted to scrubbed bytes immediately
        } catch {
            throw VaultError.wrongPassphrase
        }
        let keyBytes = unwrapped.rawRepresentation // transient: stored in the scrubbed `dataKeyBytes` field
        return VaultService(document: document, keyBytes: keyBytes)
    }
}
