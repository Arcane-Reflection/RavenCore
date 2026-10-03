import Foundation

/// The state-level native⇄kdbx mapper (05-CONTEXT D-02/D-03).
///
/// Import (`nativeVault`) turns a `KdbxDocument` — the value type produced by
/// `KdbxReader`, never a file handle — into vault-shaped content the app layer
/// materializes through `VaultService.add`/`update` chains (T-05-02: the
/// mapper cannot touch any file). Export (`kdbxDocument`) is the dual.
///
/// Mapping semantics (05-CONTEXT D-02, 05-RESEARCH R-1):
/// - kdbx group tree → `Folder` tree (the root group itself is not a folder;
///   group UUIDs are not preserved — native ids are freshly generated).
/// - entry history → same-id envelope version chain, oldest → newest; the
///   app layer replays it as `add` + per-version `update` with `at:` taken
///   from each version's KdbxTimes.
/// - entries inside the recycle-bin group (recycle bin enabled) → archived.
/// - with the recycle bin disabled, `deletedObjects` are permanent deletions
///   in kdbx semantics — they are reported, never imported.
/// - `KPEX_PASSKEY_*` passkey attributes are consumed into
///   `RecordPayload.passkey` (06-CONTEXT D-09 close-out); only a malformed
///   passkey entry keeps counting under `passkeyAttributes`. Everything else
///   the native model cannot represent (custom string attributes, auto-type,
///   custom icons) is dropped **with an honest count** in
///   `ImportSummary.skippedCounts` — never silently.
///
/// Imported records are uniformly `.password`/`.auto` (v1 has no source for
/// kdbx entry kinds); the TOTP secret is extracted when the entry carries a
/// KeePassXC `TimeOtp-Secret*` attribute or an `otpauth://` URI attribute
/// (stored only — live codes are a later phase).
public enum KdbxVaultMapper {

    // MARK: - Import summary

    /// Honest accounting of one import: what came through and what was
    /// dropped. `skippedCounts` keys are stable strings (see `SkipKey`)
    /// so the UI can label them; a zero total means nothing was dropped.
    public struct ImportSummary: Sendable, Equatable {
        /// Records imported (one per kdbx entry with a title).
        public var recordCount: Int
        /// Folders mapped from the kdbx group tree.
        public var folderCount: Int
        /// Total envelope versions written (current versions + history).
        public var versionCount: Int
        /// Attachments carried across (current versions + history versions).
        public var attachmentCount: Int
        /// Per-kind counts of dropped/unrepresentable input. Always reported
        /// — an empty dictionary means nothing was skipped.
        public var skippedCounts: [String: Int]

        /// Canonical `skippedCounts` keys.
        public enum SkipKey {
            /// Custom string attributes that have no native storage.
            public static let customFields = "customFields"
            /// Auto-type configurations.
            public static let autotype = "autotype"
            /// Malformed `KPEX_PASSKEY*` entries — a well-formed passkey
            /// imports into `RecordPayload.passkey` (D-09); only an
            /// unparseable one keeps counting here (the entry still imports).
            public static let passkeyAttributes = "passkeyAttributes"
            /// Custom icon references.
            public static let customIcons = "customIcons"
            /// Permanent deletions (recycle bin disabled) — reported, never
            /// imported (kdbx semantics).
            public static let deletedObjects = "deletedObjects"
            /// Entries without a Title — cannot render, so not imported.
            public static let emptyName = "emptyName"
            /// Groups whose name collided with a sibling and were renamed
            /// ("Name 2", "Name 3", …) because native folders require
            /// unique sibling names.
            public static let renamedFolders = "renamedFolders"
            /// Attachment references whose bytes are unreachable in the
            /// unified model (KDBX 3.1 keeps its binary pool opaque in Meta,
            /// D-06) — the entry imports without them; the loss is counted.
            public static let unresolvedAttachments = "unresolvedAttachments"
        }

        /// Total number of skipped items across all kinds.
        public var skippedTotal: Int {
            skippedCounts.values.reduce(0, +)
        }

        /// Creates a summary; used by the mapper.
        public init(
            recordCount: Int,
            folderCount: Int,
            versionCount: Int,
            attachmentCount: Int,
            skippedCounts: [String: Int]
        ) {
            self.recordCount = recordCount
            self.folderCount = folderCount
            self.versionCount = versionCount
            self.attachmentCount = attachmentCount
            self.skippedCounts = skippedCounts
        }
    }

    // MARK: - Mapped content

    /// One historical version of a mapped record (everything a versioned
    /// envelope carries). Ordered oldest → newest, excluding the current
    /// version, which rides on `MappedRecord` itself.
    public struct MappedRecordVersion: Sendable, Equatable {
        public var payload: RecordPayload
        public var tags: [String]?
        public var folderID: UUID?
        public var attachments: [RecordAttachment]?
        /// Version timestamp from the entry's KdbxTimes (see type comment).
        public var at: Date

        /// Creates a mapped version; used by the mapper.
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

    /// One mapped record: current content plus its history chain.
    public struct MappedRecord: Sendable, Equatable {
        /// Always `.password` in v1 (see type comment on `KdbxVaultMapper`).
        public var type: RecordType
        /// Always `.auto` in v1 — kdbx carries no security tiers.
        public var level: SecurityLevel
        public var payload: RecordPayload
        public var tags: [String]?
        public var folderID: UUID?
        public var attachments: [RecordAttachment]?
        /// Previous versions, oldest → newest (kdbx `history` order).
        public var historyVersions: [MappedRecordVersion]
        /// `true` when the entry sits inside the recycle-bin subtree.
        public var isArchived: Bool
        /// Timestamp of the current version (the timeline tail) — the app
        /// replay's final `update` uses it so `records()` surfaces exactly
        /// this version as newest.
        public var currentAt: Date
        /// The source entry's kdbx UUID — informational only (not imported;
        /// native ids are freshly generated).
        public var kdbxUUID: UUID

        /// Creates a mapped record; used by the mapper.
        public init(
            type: RecordType,
            level: SecurityLevel,
            payload: RecordPayload,
            tags: [String]?,
            folderID: UUID?,
            attachments: [RecordAttachment]?,
            historyVersions: [MappedRecordVersion],
            isArchived: Bool,
            currentAt: Date,
            kdbxUUID: UUID
        ) {
            self.type = type
            self.level = level
            self.payload = payload
            self.tags = tags
            self.folderID = folderID
            self.attachments = attachments
            self.historyVersions = historyVersions
            self.isArchived = isArchived
            self.currentAt = currentAt
            self.kdbxUUID = kdbxUUID
        }
    }

    /// The full import result: folders (parents before children), records,
    /// and the honest skip accounting.
    public struct MappedVaultContent: Sendable, Equatable {
        public var folders: [Folder]
        public var records: [MappedRecord]
        public var summary: ImportSummary

        /// Creates mapped content; used by the mapper.
        public init(folders: [Folder], records: [MappedRecord], summary: ImportSummary) {
            self.folders = folders
            self.records = records
            self.summary = summary
        }
    }

    // MARK: - Import (kdbx → native)

    /// Maps a read `KdbxDocument` to vault-shaped content. Throws typed
    /// `InteropError`s for structural failures (empty root/group names,
    /// oversized attachments); per-entry data gaps are counted, not thrown.
    public static func nativeVault(from document: KdbxDocument) throws -> MappedVaultContent {
        // A root group without a name cannot anchor the tree mapping.
        guard !document.root.name.isEmpty else { throw InteropError.unsupportedKdbx }

        var skipped: [String: Int] = [:]
        func count(_ key: String, _ n: Int = 1) {
            skipped[key, default: 0] += n
        }

        // Permanent deletions (recycle bin disabled): kdbx records them as
        // DeletedObjects — the objects are gone from the tree, so there is
        // nothing to import; report the count honestly (R-1 pitfall 2).
        if document.meta.recycleBinEnabled == false, !document.deletedObjects.isEmpty {
            count(ImportSummary.SkipKey.deletedObjects, document.deletedObjects.count)
        }

        // Group tree → folders (parents before children). The recycle-bin
        // group is part of the tree and maps like any group; its entries
        // become archived records below.
        let (folders, folderIDByGroupUUID) = try mapFolders(document.root, skipped: &skipped)

        // Entries → records. Ancestor tracking decides the archived state.
        let recycled = document.meta.recycleBinEnabled == true ? document.meta.recycleBinUUID : nil
        var records: [MappedRecord] = []
        var versionCount = 0
        var attachmentCount = 0
        try mapEntries(
            in: document.root,
            folderID: nil,
            insideRecycleBin: false,
            recycleBinUUID: recycled,
            folderIDByGroupUUID: folderIDByGroupUUID,
            document: document,
            skipped: &skipped,
            versionCount: &versionCount,
            attachmentCount: &attachmentCount,
            into: &records)

        let summary = ImportSummary(
            recordCount: records.count,
            folderCount: folders.count,
            versionCount: versionCount,
            attachmentCount: attachmentCount,
            skippedCounts: skipped)
        return MappedVaultContent(folders: folders, records: records, summary: summary)
    }

    // MARK: - Group tree → folders

    /// Depth-first folder mapping; parents are appended before their
    /// children so the app layer can `addFolder` in array order. Sibling
    /// names are uniqued natively ("Name" → "Name 2") because native
    /// folders require sibling-unique names; each rename is counted.
    /// Returns the folders plus the kdbx-group-UUID → native-folder-id map
    /// the entry pass needs to place records.
    private static func mapFolders(
        _ root: KdbxGroup,
        skipped: inout [String: Int]
    ) throws -> (folders: [Folder], folderIDByGroupUUID: [UUID: UUID]) {
        var folders: [Folder] = []
        var folderIDByGroupUUID: [UUID: UUID] = [:]
        var siblingNames: [UUID?: Set<String>] = [:]

        func walk(_ group: KdbxGroup, parentID: UUID?) throws {
            let clean = group.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !clean.isEmpty else { throw InteropError.emptyName }
            let name = uniqueName(clean, among: &siblingNames[parentID], skipped: &skipped)
            let folder = Folder(id: UUID(), name: name, parentID: parentID)
            folders.append(folder)
            folderIDByGroupUUID[group.uuid] = folder.id
            for child in group.groups {
                try walk(child, parentID: folder.id)
            }
        }
        for group in root.groups {
            try walk(group, parentID: nil)
        }
        return (folders, folderIDByGroupUUID)
    }

    private static func uniqueName(
        _ name: String,
        among seen: inout Set<String>?,
        skipped: inout [String: Int]
    ) -> String {
        let taken = seen ?? []
        if !taken.contains(name) {
            seen = taken.union([name])
            return name
        }
        var counter = 2
        while taken.contains("\(name) \(counter)") { counter += 1 }
        let renamed = "\(name) \(counter)"
        seen = taken.union([renamed])
        skipped[ImportSummary.SkipKey.renamedFolders, default: 0] += 1
        return renamed
    }

    // MARK: - Entries → records

    private static func mapEntries(
        in group: KdbxGroup,
        folderID: UUID?,
        insideRecycleBin: Bool,
        recycleBinUUID: UUID?,
        folderIDByGroupUUID: [UUID: UUID],
        document: KdbxDocument,
        skipped: inout [String: Int],
        versionCount: inout Int,
        attachmentCount: inout Int,
        into records: inout [MappedRecord]
    ) throws {
        let inRecycleBin = insideRecycleBin || group.uuid == recycleBinUUID
        for entry in group.entries {
            // Entries without a Title cannot render — count, don't import
            // (honest accounting beats a typed abort for data, T-05-02).
            let title = entry.name ?? ""
            guard !title.isEmpty else {
                skipped[ImportSummary.SkipKey.emptyName, default: 0] += 1
                continue
            }

            // KeePassXC passkey entries import with their credential intact
            // (06-CONTEXT D-09 close-out): `mapVersion` consumes the
            // KPEX_PASSKEY_* attributes into `payload.passkey` for the
            // current and history versions alike; only a malformed passkey
            // keeps counting under `passkeyAttributes`.
            // KeePassXC writes a default AutoType shell (`Enabled=true`,
            // `DefaultSequence=""`, no associations) on EVERY entry — only an
            // explicit user configuration (non-empty sequence, associations,
            // or disabled auto-type) is a real loss worth counting.
            if let autoType = entry.autoType,
               !(autoType.defaultSequence ?? "").isEmpty
                   || !autoType.associations.isEmpty
                   || autoType.enabled == false {
                skipped[ImportSummary.SkipKey.autotype, default: 0] += 1
            }
            if entry.customIconUUID != nil {
                skipped[ImportSummary.SkipKey.customIcons, default: 0] += 1
            }
            countCustomFields(in: entry, skipped: &skipped)

            // Monotonic version timeline: kdbx times when present, import
            // time as the fallback, bumped +1s so the chain stays strictly
            // increasing (R-1 pitfall 1 — order decides which version wins).
            let fallbackBase = Date()
            var timeline = Timeline(fallbackBase: fallbackBase)

            var versions: [MappedRecordVersion] = []
            for historic in entry.history {
                let mapped = try mapVersion(
                    historic, folderID: folderID, document: document,
                    timeline: &timeline, skipped: &skipped)
                versions.append(mapped)
                versionCount += 1
                attachmentCount += mapped.attachments?.count ?? 0
            }

            let current = try mapVersion(
                entry, folderID: folderID, document: document,
                timeline: &timeline, skipped: &skipped)
            versionCount += 1
            attachmentCount += current.attachments?.count ?? 0

            records.append(MappedRecord(
                type: .password,
                level: .auto,
                payload: current.payload,
                tags: current.tags,
                folderID: current.folderID,
                attachments: current.attachments,
                historyVersions: versions,
                isArchived: inRecycleBin,
                currentAt: current.at,
                kdbxUUID: entry.uuid))
        }
        for child in group.groups {
            try mapEntries(
                in: child,
                folderID: folderIDByGroupUUID[child.uuid],
                insideRecycleBin: inRecycleBin,
                recycleBinUUID: recycleBinUUID,
                folderIDByGroupUUID: folderIDByGroupUUID,
                document: document,
                skipped: &skipped, versionCount: &versionCount,
                attachmentCount: &attachmentCount, into: &records)
        }
    }

    /// Counts custom string attributes the native model cannot store:
    /// everything outside the standard five keys except passkey attributes
    /// (counted separately) and consumed TOTP secrets (kept, not dropped).
    private static let standardStringKeys: Set<String> = ["Title", "UserName", "Password", "URL", "Notes"]

    private static func countCustomFields(in entry: KdbxEntry, skipped: inout [String: Int]) {
        var consumedOtpauth = false
        for string in entry.strings {
            let key = string.key
            if standardStringKeys.contains(key) { continue }
            if key.hasPrefix("KPEX_PASSKEY") { continue } // passkeyAttributes
            if key == "TimeOtp-Secret-Base32" || key == "TimeOtp-Secret" || key == "TimeOtp-Secret-Hex" {
                continue // consumed into payload.totpSecret
            }
            if string.value.hasPrefix("otpauth://") {
                // The first otpauth attribute feeds totpSecret; extras are drops.
                if consumedOtpauth {
                    skipped[ImportSummary.SkipKey.customFields, default: 0] += 1
                }
                consumedOtpauth = true
                continue
            }
            skipped[ImportSummary.SkipKey.customFields, default: 0] += 1
        }
    }

    private static func mapVersion(
        _ entry: KdbxEntry,
        folderID: UUID?,
        document: KdbxDocument,
        timeline: inout Timeline,
        skipped: inout [String: Int]
    ) throws -> MappedRecordVersion {
        let payload = RecordPayload(
            title: entry.name ?? "",
            username: entry.username ?? "",
            password: entry.password ?? "",
            notes: entry.notes ?? "",
            totpSecret: totpSecret(in: entry),
            seedPhrase: nil,
            url: entry.url,
            passkey: passkeyCredential(in: entry, skipped: &skipped))
        let tags = mappedTags(entry.tags)

        var attachments: [RecordAttachment]? = nil
        if !entry.binaries.isEmpty {
            var mapped: [RecordAttachment] = []
            for reference in entry.binaries {
                guard reference.ref >= 0, reference.ref < document.binaries.count else {
                    // Unreachable bytes (KDBX 3.1 keeps its binary pool
                    // opaque in Meta, D-06): the entry imports without the
                    // attachment and the loss is counted — never silent.
                    skipped[ImportSummary.SkipKey.unresolvedAttachments, default: 0] += 1
                    continue
                }
                let content = document.binaries[reference.ref].content
                guard content.count <= KdbxAttachments.sizeLimitBytes else {
                    throw InteropError.attachmentTooLarge
                }
                mapped.append(RecordAttachment(
                    id: UUID(), name: reference.key, contentType: nil, data: content))
            }
            attachments = mapped.isEmpty ? nil : mapped
        }

        return MappedRecordVersion(
            payload: payload,
            tags: tags,
            folderID: folderID,
            attachments: attachments,
            at: timeline.advance(preferred: entry.times?.lastModificationTime
                ?? entry.times?.creationTime))
    }

    // MARK: - Field helpers

    /// Splits the space-separated kdbx tag string; empty/absent → nil.
    static func mappedTags(_ raw: String?) -> [String]? {
        guard let raw else { return nil }
        let tags = raw.split(separator: " ").map(String.init).filter { !$0.isEmpty }
        return tags.isEmpty ? nil : tags
    }

    /// Extracts the stored TOTP secret: KeePassXC `TimeOtp-Secret*`
    /// attributes first, then any attribute whose value is an `otpauth://`
    /// URI — the URI branch delegates to `OTPAuthURIParser.secret(in:)`
    /// (06-02 D-07 hoist: one parser for CSV import, kdbx import, and live
    /// code generation). Returns nil when absent.
    static func totpSecret(in entry: KdbxEntry) -> String? {
        for key in ["TimeOtp-Secret-Base32", "TimeOtp-Secret", "TimeOtp-Secret-Hex"] {
            if let value = entry.value(key), !value.isEmpty { return value }
        }
        for string in entry.strings where string.value.hasPrefix("otpauth://") {
            if let secret = OTPAuthURIParser.secret(in: string.value) {
                return secret
            }
        }
        return nil
    }

    /// Reads the passkey credential for the payload (06-CONTEXT D-09
    /// close-out): a well-formed passkey entry yields its `PasskeyCredential`
    /// (current and history versions alike — kdbx history can carry
    /// passkeys). A malformed passkey entry imports without the credential
    /// and counts once under `SkipKey.passkeyAttributes` — the loss is
    /// named, never thrown (honest accounting beats aborting for data).
    private static func passkeyCredential(
        in entry: KdbxEntry,
        skipped: inout [String: Int]
    ) -> PasskeyCredential? {
        guard KdbxPasskey.isPasskey(entry) else { return nil }
        do {
            return try KdbxPasskey.read(from: entry)
        } catch {
            skipped[ImportSummary.SkipKey.passkeyAttributes, default: 0] += 1
            return nil
        }
    }

    // MARK: - Export (native → kdbx)

    /// The export default-exclusion predicate (05-CONTEXT D-05): L2 Custom
    /// tier and seed phrase records are excluded by default; the export
    /// sheet lists every excluded record for explicit per-record inclusion.
    /// Categorical by design — the Phase 7 Emergency Card isolation joins
    /// this same predicate later (no second code path).
    ///
    /// 07-04 (D-16): `emergencyCard` is additionally excluded here as
    /// DEFENSE IN DEPTH only. The hard exclusion (no per-record Include
    /// override, unlike the level-based defaults above) lives in the app
    /// layer's export-input assembly behind the single
    /// `EmergencyCardPolicy.isEmergencyCard` classification — this engine
    /// clause cannot be the sole guard because a UI include toggle could
    /// otherwise override it.
    public static func isDefaultExcluded(_ record: DecryptedRecord) -> Bool {
        record.level == .custom || record.type == .seedPhrase || record.type == .emergencyCard
    }

    /// Everything the export mapper needs. The caller filters by the D-05
    /// predicate and the user's explicit Include choices — `includedIDs` is
    /// the final say on which records leave the vault.
    public struct ExportInput: Sendable, Equatable {
        /// Deduplicated record view (newest version per id), as produced by
        /// `VaultService.records()` — archived records included (D-05: they
        /// export as ordinary entries).
        public var records: [DecryptedRecord]
        /// Per-id prior versions, oldest → newest, EXCLUDING the newest
        /// (which rides `records`) — as produced by
        /// `VaultService.allVersions()`.
        public var versions: [UUID: [RecordVersion]]
        /// Folder tree (parents before children, as stored).
        public var folders: [Folder]
        /// Records to export (predicate-filtered + user-included).
        public var includedIDs: Set<UUID>

        /// Creates export input.
        public init(
            records: [DecryptedRecord],
            versions: [UUID: [RecordVersion]],
            folders: [Folder],
            includedIDs: Set<UUID>
        ) {
            self.records = records
            self.versions = versions
            self.folders = folders
            self.includedIDs = includedIDs
        }
    }

    /// Maps vault content to a `KdbxDocument` plus its file-level binary
    /// pool (feed both to `KdbxWriter.write`). The dual of `nativeVault`:
    /// folders → group tree, versions → entry history (old → new), records
    /// → entries with the five standard fields; archived records export as
    /// ordinary entries (D-05) and the recycle-bin group is not constructed.
    public static func kdbxDocument(
        from input: ExportInput
    ) throws -> (document: KdbxDocument, binaries: [KdbxInnerHeader.Binary]) {
        var document = KdbxDocument()
        document.meta.generator = "RavenVault"
        // kdbx has no archive concept: exported files enable the recycle bin
        // like any KeePassXC database, but we never construct the group —
        // archived records export as ordinary entries (D-05).
        document.meta.recycleBinEnabled = true

        // Shared attachment pool (kdbx history entries share the file-level
        // pool); identical content is pooled once.
        var pool: [KdbxInnerHeader.Binary] = []
        var poolIndexByContent: [Data: Int] = [:]
        func poolRef(_ attachment: RecordAttachment) -> KdbxBinaryReference {
            if let index = poolIndexByContent[attachment.data] {
                return KdbxBinaryReference(key: attachment.name, ref: index)
            }
            let index = pool.count
            pool.append(KdbxInnerHeader.Binary(flags: 0x01, content: attachment.data))
            poolIndexByContent[attachment.data] = index
            return KdbxBinaryReference(key: attachment.name, ref: index)
        }

        // Entries → their target folder bucket (nil = root). Unknown folder
        // references fail typed — re-parenting silently would lose data.
        var folderIDs = Set(input.folders.map(\.id))
        var entriesByFolder: [UUID?: [KdbxEntry]] = [:]
        for record in input.records where input.includedIDs.contains(record.id) {
            if let folderID = record.folderID, !folderIDs.contains(folderID) {
                // Unreachable through engine invariants (deleteFolder
                // refuses referenced folders) — fail typed, never silently
                // re-parent the record.
                throw InteropError.mappingFailed
            }
            let entry = try makeEntry(record: record, versions: input.versions[record.id] ?? [], poolRef: poolRef)
            entriesByFolder[record.folderID, default: []].append(entry)
        }

        // Folders → group tree, assembled bottom-up (KdbxGroup is a value
        // type): children first, entries attached at each level. A parent
        // reference that never resolves fails typed.
        var childrenByParent: [UUID?: [Folder]] = Dictionary(grouping: input.folders, by: \.parentID)
        var visited = 0
        func assemble(_ folder: Folder) -> KdbxGroup {
            visited += 1
            var group = KdbxGroup(name: folder.name)
            for child in childrenByParent[folder.id] ?? [] {
                group.groups.append(assemble(child))
            }
            group.entries = entriesByFolder[folder.id] ?? []
            return group
        }
        for rootFolder in childrenByParent[nil] ?? [] {
            document.root.groups.append(assemble(rootFolder))
        }
        guard visited == input.folders.count else {
            throw InteropError.mappingFailed // orphaned parent chain
        }

        document.root.entries = entriesByFolder[nil] ?? []
        return (document, pool)
    }

    /// Builds one entry (standard fields, tags, times, history, attachment
    /// refs, passkey attributes) from a record plus its prior versions. The
    /// five standard fields are always emitted (empty string when absent) —
    /// KeePassXC's own emission convention, so KeePassXC-side comparisons
    /// see no difference.
    private static func writeStandardFields(_ payload: RecordPayload, into entry: inout KdbxEntry) {
        entry.setValue("Title", payload.title)
        entry.setValue("UserName", payload.username)
        entry.setValue("Password", payload.password, protected: true)
        entry.setValue("URL", payload.url ?? "")
        entry.setValue("Notes", payload.notes)
    }

    private static func makeEntry(
        record: DecryptedRecord,
        versions: [RecordVersion],
        poolRef: (RecordAttachment) -> KdbxBinaryReference
    ) throws -> KdbxEntry {
        var entry = KdbxEntry()
        writeStandardFields(record.payload, into: &entry)
        if let tags = record.tags, !tags.isEmpty {
            entry.tags = tags.joined(separator: " ")
        }
        if let passkey = record.payload.passkey {
            // Passkey write-back (06-CONTEXT D-09 close-out): the byte-level
            // canonical KPEX_PASSKEY_* attribute set + KeePassXC protection
            // layout + entry shell (Title/UserName/URL/icon 13/"Passkey" tag)
            // per the Phase 2 kxc oracle — an exported passkey record is
            // indistinguishable from a KeePassXC-created one. Emitted after
            // the generic fields so the oracle shell is the final word.
            try KdbxPasskey.write(
                passkey, into: &entry,
                title: record.payload.title, originURL: record.payload.url)
        }

        let creation = versions.first?.at ?? record.createdAt
        entry.times = KdbxTimes.make(creation: creation, lastModification: record.createdAt)

        for version in versions { // oldest → newest; newest rides the entry body
            var historic = KdbxEntry()
            writeStandardFields(version.payload, into: &historic)
            if let tags = version.tags, !tags.isEmpty {
                historic.tags = tags.joined(separator: " ")
            }
            if let passkey = version.payload.passkey {
                // History versions mirror the current-version treatment:
                // kdbx history can carry passkeys, so each version rewrites
                // its own canonical KPEX attribute set (D-09 close-out).
                try KdbxPasskey.write(
                    passkey, into: &historic,
                    title: version.payload.title, originURL: version.payload.url)
            }
            historic.times = KdbxTimes.make(creation: creation, lastModification: version.at)
            if let attachments = version.attachments {
                historic.binaries = attachments.map(poolRef)
            }
            entry.history.append(historic)
        }

        if let attachments = record.attachments {
            entry.binaries = attachments.map(poolRef)
        }
        return entry
    }

    // MARK: - Shared helpers

    /// Monotonic version-timeline helper: preferred dates when they keep the
    /// chain increasing, otherwise the fallback base bumped by whole seconds.
    struct Timeline {
        let fallbackBase: Date
        private var last: Date?

        init(fallbackBase: Date) {
            self.fallbackBase = fallbackBase
        }

        mutating func advance(preferred: Date?) -> Date {
            var next = preferred ?? fallbackBase
            if let last, next <= last {
                next = last.addingTimeInterval(1)
            }
            last = next
            return next
        }
    }
}

/// Small construction helper for the mapper's timestamp bookkeeping.
private extension KdbxTimes {
    static func make(creation: Date?, lastModification: Date?) -> KdbxTimes {
        var times = KdbxTimes()
        times.creationTime = creation
        times.lastModificationTime = lastModification
        return times
    }
}
