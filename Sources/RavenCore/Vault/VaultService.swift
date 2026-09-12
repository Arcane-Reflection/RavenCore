import CryptoKit
import Foundation

/// Errors thrown by the vault engine. All `Equatable` for exact-case test
/// assertions; failures never distinguish which credential half was wrong.
public enum VaultError: Error, Equatable {
    case wrongPassphrase
    case locked
    case corruptDocument
    case recordNotFound
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
    private var dataKey: SymmetricKey?

    /// `true` while the data key is held in memory.
    public var isUnlocked: Bool { dataKey != nil }
    /// Hash of the newest log entry.
    public var headHash: Data { document.header.headHash }

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
        let dataKey = SymmetricKey(size: .bits256)
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
            let wrapped = try AESGCMCipher.encrypt(dataKey.rawRepresentation, key: SymmetricKey(data: kekData))
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
            let wrapped = try AESGCMCipher.encrypt(dataKey.rawRepresentation, key: SymmetricKey(data: kekData))
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
        return VaultService(document: VaultDocument(header: finalHeader, log: log), dataKey: dataKey)
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
            // and future presets (D-02) keep huge headroom, so these policy
            // caps keep a tampered header from triggering a jetsam-scale
            // Argon2 allocation on iOS instead of a clean typed failure.
            guard memoryKiB <= 1_048_576, timeCost <= 1 << 24, parallelism <= 16 else {
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
        let service = VaultService(document: document, dataKey: SymmetricKey(data: keyData))
        // D-04: capture the legacy passphrase so the next save can upgrade the
        // header to Argon2id. Consumed (and scrubbed) by upgradeIfNeeded.
        if document.header.formatVersion < VaultService.formatVersion,
           document.header.kdfAlgorithm == VaultKDF.pbkdf2 {
            service.legacyPassphrase = Data(passphrase.utf8)
        }
        return service
    }

    init(document: VaultDocument, dataKey: SymmetricKey?) {
        self.document = document
        self.dataKey = dataKey
    }

    /// Clears the data key from memory.
    public func lock() {
        dataKey = nil
        if legacyPassphrase != nil {
            SecureMemory.zero(&legacyPassphrase!)
            legacyPassphrase = nil
        }
    }

    // MARK: - Records

    @discardableResult
    /// Appends a record (payload encrypted under the data key) to the log.
    /// - Returns: the new record’s identifier.
    public func add(
        _ type: RecordType,
        level: SecurityLevel,
        payload: RecordPayload,
        at date: Date = Date()
    ) throws -> UUID {
        guard let dataKey else { throw VaultError.locked }
        let envelope = RecordEnvelope(type: type, level: level, record: payload)
        let sealed = try AESGCMCipher.encrypt(try JSONEncoder().encode(envelope), key: dataKey)
        let entry = document.log.append(payload: try JSONEncoder().encode(sealed), at: date)
        document.header.headHash = document.log.headHash
        return entry.id
    }

    /// Decrypts and returns the full history (including archived records).
    public func records() throws -> [DecryptedRecord] {
        guard let dataKey else { throw VaultError.locked }
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
                isArchived: entry.isArchived
            )
        }
    }

    /// Decrypts and returns the non-archived records.
    public func activeRecords() throws -> [DecryptedRecord] {
        try records().filter { !$0.isArchived }
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

    // MARK: - KDF migration (D-03/D-04)

    /// Transient passphrase of a legacy (v1) vault, captured at unlock and
    /// consumed by the save-time upgrade. Never persisted; held as Data so the
    /// upgrade can re-derive the Argon2id KEK without keeping a String alive.
    private var legacyPassphrase: Data?

    /// Re-wraps the data key under a fresh Argon2id KEK (new salt, D-01
    /// defaults) and marks the header formatVersion 2. Requires unlocked
    /// state; the log is untouched — this is a header-only operation.
    public func rewrap(passphrase: String) throws {
        guard let dataKey else { throw VaultError.locked }
        try rewrapHeader(dataKey: dataKey, kekPassword: Data(passphrase.utf8))
    }

    /// Upgrades a legacy (v1) header to Argon2id when serializing an unlocked
    /// vault (D-04: save = upgrade), using the passphrase captured at unlock.
    /// Locked vaults serialize unchanged — there is neither a data key nor a
    /// captured passphrase to re-wrap with.
    private func upgradeIfNeeded() throws {
        guard isUnlocked,
              document.header.formatVersion < VaultService.formatVersion,
              let passphrase = legacyPassphrase, !passphrase.isEmpty else { return }
        try rewrapHeader(dataKey: dataKey!, kekPassword: passphrase)
        SecureMemory.zero(&legacyPassphrase!)
        legacyPassphrase = nil
    }

    private func rewrapHeader(dataKey: SymmetricKey, kekPassword: Data) throws {
        guard !kekPassword.isEmpty else { throw VaultError.wrongPassphrase }
        let salt = SecureRandom.bytes(count: 16)
        let kekData = try KeyDerivation.argon2id(
            password: kekPassword,
            salt: salt,
            memoryKiB: KeyDerivation.argon2MemoryKiB,
            timeCost: KeyDerivation.argon2TimeCost,
            parallelism: KeyDerivation.argon2Parallelism
        )
        document.header.wrappedDataKey = try AESGCMCipher.encrypt(dataKey.rawRepresentation, key: SymmetricKey(data: kekData))
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
    public func attachDeviceWrap(using provider: WrappingKeyProvider) throws {
        guard let dataKey else { throw VaultError.locked }
        document.header.deviceWrappedDataKey = try provider.wrap(dataKey)
    }

    /// Unlocks using the device wrap (e.g. after Secure Enclave biometric auth).
    public static func unlockWithDeviceWrap(serializedDocument: Data, provider: WrappingKeyProvider) throws -> VaultService {
        guard let document = try? JSONDecoder().decode(VaultDocument.self, from: serializedDocument),
              let deviceWrapped = document.header.deviceWrappedDataKey else {
            throw VaultError.corruptDocument
        }
        let dataKey: SymmetricKey
        do {
            dataKey = try provider.unwrap(deviceWrapped)
        } catch {
            throw VaultError.wrongPassphrase
        }
        return VaultService(document: document, dataKey: dataKey)
    }
}
