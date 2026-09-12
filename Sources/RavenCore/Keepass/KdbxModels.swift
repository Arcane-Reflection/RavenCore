import Foundation

/// KDBX format version (major, minor).
public struct KdbxVersion: Sendable, Equatable {
    /// Major version (the critical bits used for reader/writer gating).
    public var major: UInt32
    /// Minor version (informational).
    public var minor: UInt32

    /// Read-only legacy version — 3.1 files are read (D-05), never written.
    public static let v31 = KdbxVersion(major: 3, minor: 1)
    /// The version this writer emits (3.1-sourced documents upgrade to it, D-05).
    public static let v40 = KdbxVersion(major: 4, minor: 0)
    /// Accepted on read; only written when explicitly requested via options.
    public static let v41 = KdbxVersion(major: 4, minor: 1)

    /// Creates a version from its numeric parts.
    public init(major: UInt32, minor: UInt32) {
        self.major = major
        self.minor = minor
    }
}

// MARK: - Opaque preservation (D-06)

/// An unrecognized header field (ID + raw value), replayed verbatim on write.
public struct OpaqueField: Sendable, Equatable {
    /// Raw field ID as it appeared on the wire.
    public var id: UInt8
    /// Raw field payload, uninterpreted.
    public var value: Data

    /// Creates an opaque field from wire parts.
    public init(id: UInt8, value: Data) {
        self.id = id
        self.value = value
    }
}

/// An unrecognized attribute carried by a recognized element.
public struct OpaqueAttribute: Sendable, Equatable {
    /// Attribute name.
    public var name: String
    /// Attribute value.
    public var value: String

    /// Creates an opaque attribute.
    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

/// Unrecognized attributes carried by a *recognized* element.
public typealias UnknownAttributes = [OpaqueAttribute]

/// An unrecognized XML subtree, preserved structurally (element names,
/// attributes, text, children) and re-serialized on write.
public struct OpaqueNode: Sendable, Equatable {
    /// Element name.
    public var name: String
    /// Attributes, in preserved order.
    public var attributes: [OpaqueAttribute]
    /// Concatenated text/CDATA content.
    public var text: String
    /// Nested opaque subtrees.
    public var children: [OpaqueNode]

    /// Creates an opaque subtree node.
    public init(name: String, attributes: [OpaqueAttribute] = [], text: String = "", children: [OpaqueNode] = []) {
        self.name = name
        self.attributes = attributes
        self.text = text
        self.children = children
    }
}

// MARK: - Document

/// The unified in-memory KDBX database model. 4.x files map natively;
/// 3.1 files are read into the same model and tagged with their version (D-05).
public struct KdbxDocument: Sendable, Equatable {
    /// Version the document was read from.
    public var version: KdbxVersion
    /// Database metadata.
    public var meta: KdbxMeta
    /// Root group holding the entry/group tree.
    public var root: KdbxGroup
    /// Deletion records for objects removed with the recycle bin disabled.
    public var deletedObjects: [KdbxDeletedObject]
    /// File-level attachment pool (inner header binaries); entries reference
    /// these by index. Carried on the document so a read→write round trip is
    /// lossless (D-07).
    public var binaries: [KdbxInnerHeader.Binary] = []
    /// Unrecognized KeePassFile attributes, replayed on write (D-06).
    public var unknownAttributes: UnknownAttributes = []

    /// Creates an empty document (4.0, single root group).
    public init(version: KdbxVersion = .v40, meta: KdbxMeta = KdbxMeta(), root: KdbxGroup = KdbxGroup(name: "Root"), deletedObjects: [KdbxDeletedObject] = []) {
        self.version = version
        self.meta = meta
        self.root = root
        self.deletedObjects = deletedObjects
    }
}

/// A recycle-bin deletion record (spec DeletedObject).
public struct KdbxDeletedObject: Sendable, Equatable {
    /// UUID of the deleted object.
    public var uuid: UUID
    /// When the object was deleted, if recorded.
    public var deletionTime: Date?

    /// Creates a deletion record.
    public init(uuid: UUID, deletionTime: Date? = nil) {
        self.uuid = uuid
        self.deletionTime = deletionTime
    }
}

// MARK: - Meta

/// Meta memory-protection flags (`nil` = attribute absent).
public struct KdbxMemoryProtection: Sendable, Equatable {
    /// Protect Title values on display.
    public var protectTitle: Bool?
    /// Protect UserName values.
    public var protectUserName: Bool?
    /// Protect Password values.
    public var protectPassword: Bool?
    /// Protect URL values.
    public var protectURL: Bool?
    /// Protect Notes values.
    public var protectNotes: Bool?

    /// Creates default (all-absent) protection flags.
    public init() {}
}

/// A custom PNG icon (spec CustomIcons).
public struct KdbxCustomIcon: Sendable, Equatable {
    /// Icon identity, referenced by entries/groups via `customIconUUID`.
    public var uuid: UUID
    /// Raw PNG bytes.
    public var pngData: Data

    /// Creates a custom icon.
    public init(uuid: UUID, pngData: Data) {
        self.uuid = uuid
        self.pngData = pngData
    }
}

/// Database metadata (spec Meta). Unrecognized children ride `unknownXml` (D-06).
public struct KdbxMeta: Sendable, Equatable {
    /// Creating application ("KeePassXC 2.7.12" etc.).
    public var generator: String?
    /// Human-readable database name.
    public var databaseName: String?
    /// Last database-name modification time.
    public var databaseNameChanged: Date?
    /// Display-protection flags.
    public var memoryProtection = KdbxMemoryProtection()
    /// Custom PNG icon pool.
    public var customIcons: [KdbxCustomIcon] = []
    /// Whether the recycle bin is enabled.
    public var recycleBinEnabled: Bool?
    /// The recycle bin group’s UUID.
    public var recycleBinUUID: UUID?
    /// Last recycle-bin setting change time.
    public var recycleBinChanged: Date?
    /// Entry-templates group UUID, if configured.
    public var entryTemplatesGroup: UUID?
    /// Maximum history entries kept per entry (-1 = unlimited).
    public var historyMaxItems: Int?
    /// Maximum history size in bytes (-1 = unlimited).
    public var historyMaxSize: Int?
    /// Last settings change time.
    public var settingsChanged: Date?
    /// Name/value plugin data (spec CustomData).
    public var customData: [String: String] = [:]
    /// Unrecognized Meta children, preserved structurally (D-06).
    public var unknownXml: [OpaqueNode] = []
    /// Unrecognized Meta attributes (D-06).
    public var unknownAttributes: UnknownAttributes = []

    /// Creates empty metadata.
    public init() {}
}

// MARK: - Group / Entry

/// A group (folder) in the entry tree (spec Group).
public struct KdbxGroup: Sendable, Equatable {
    /// Group identity (random for freshly constructed groups).
    public var uuid: UUID
    /// Display name.
    public var name: String
    /// Free-form notes, if present.
    public var notes: String?
    /// Timestamp bookkeeping, if present.
    public var times: KdbxTimes?
    /// UI expansion state, if present.
    public var isExpanded: Bool?
    /// Default auto-type sequence inherited by entries, if present.
    public var defaultAutoTypeSequence: String?
    /// Auto-type enablement (`nil` = inherit).
    public var enableAutoType: Bool?
    /// Searching enablement (`nil` = inherit).
    public var enableSearching: Bool?
    /// Last top-visible entry UUID (UI state).
    public var lastTopVisibleEntry: UUID?
    /// Custom icon reference, if any.
    public var customIconUUID: UUID?
    /// Name/value plugin data.
    public var customData: [String: String] = [:]
    /// Direct child entries.
    public var entries: [KdbxEntry] = []
    /// Direct child subgroups.
    public var groups: [KdbxGroup] = []
    /// Unrecognized Group children, preserved structurally (D-06).
    public var unknownXml: [OpaqueNode] = []
    /// Unrecognized Group attributes (D-06).
    public var unknownAttributes: UnknownAttributes = []

    /// Creates a group with a fresh random UUID.
    public init(name: String, uuid: UUID = UUID()) {
        self.name = name
        self.uuid = uuid
    }

    /// All entries in this group and (recursively) its subgroups.
    public func allEntries() -> [KdbxEntry] {
        entries + groups.flatMap { $0.allEntries() }
    }
}

/// An entry: standard fields, custom strings, attachments, and history (spec Entry).
/// Passkey attributes ride `strings` — see `KdbxPasskey`.
public struct KdbxEntry: Sendable, Equatable {
    /// Entry identity (random for freshly constructed entries).
    public var uuid: UUID
    /// Built-in icon index, if present.
    public var iconId: UInt64?
    /// Custom icon reference, if any.
    public var customIconUUID: UUID?
    /// Foreground color hint, if present.
    public var foregroundColor: String?
    /// Background color hint, if present.
    public var backgroundColor: String?
    /// URL override for auto-type, if present.
    public var overrideURL: String?
    /// Space-separated tag list, if present.
    public var tags: String?
    /// Timestamp bookkeeping, if present.
    public var times: KdbxTimes?
    /// All key/value strings — standard fields and custom attributes alike.
    public var strings: [KdbxString] = []
    /// Attachment references (indices into the document binary pool).
    public var binaries: [KdbxBinaryReference] = []
    /// Auto-type configuration, if present.
    public var autoType: KdbxAutoType?
    /// Previous versions of this entry (spec History).
    public var history: [KdbxEntry] = []
    /// Name/value plugin data.
    public var customData: [String: String] = [:]
    /// Unrecognized Entry children, preserved structurally (D-06).
    public var unknownXml: [OpaqueNode] = []
    /// Unrecognized Entry attributes (D-06).
    public var unknownAttributes: UnknownAttributes = []

    /// Creates an entry with a fresh random UUID.
    public init(uuid: UUID = UUID()) {
        self.uuid = uuid
    }

    /// Convenience lookup of a standard field's plaintext value.
    public func value(_ key: String) -> String? {
        strings.first { $0.key == key }?.value
    }

    // Semantic accessors over the standard field names.
    /// The Title standard field, if present.
    public var name: String? { value("Title") }
    /// The UserName standard field, if present.
    public var username: String? { value("UserName") }
    /// The Password standard field, if present.
    public var password: String? { value("Password") }
    /// The URL standard field, if present.
    public var url: String? { value("URL") }
    /// The Notes standard field, if present.
    public var notes: String? { value("Notes") }
    /// Attachment references (alias for `binaries`).
    public var attachments: [KdbxBinaryReference] { binaries }
    /// Number of stored history versions.
    public var historyCount: Int { history.count }

    /// Sets (or appends) a standard/custom string, preserving an existing
    /// value’s protection flag on update.
    public mutating func setValue(_ key: String, _ value: String, protected: Bool = false) {
        if let idx = strings.firstIndex(where: { $0.key == key }) {
            strings[idx].value = value
        } else {
            strings.append(KdbxString(key: key, value: value, protected: protected))
        }
    }
}

/// One key/value string of an entry, with its protection flag.
public struct KdbxString: Sendable, Equatable {
    /// Field key ("Title", "KPEX_PASSKEY_USERNAME", …).
    public var key: String
    /// Plaintext field value (protected values are decrypted at read time).
    public var value: String
    /// XML `Protected="True"` — the on-disk value rides the protection stream.
    public var protected: Bool

    /// Creates a string field.
    public init(key: String, value: String, protected: Bool = false) {
        self.key = key
        self.value = value
        self.protected = protected
    }
}

/// An entry’s reference to an attachment (spec Binary element).
public struct KdbxBinaryReference: Sendable, Equatable {
    /// File name as displayed.
    public var key: String
    /// Index into the file-level binary pool (inner header, 0-based).
    public var ref: Int

    /// Creates an attachment reference.
    public init(key: String, ref: Int) {
        self.key = key
        self.ref = ref
    }
}

/// Auto-type configuration (spec AutoType).
public struct KdbxAutoType: Sendable, Equatable {
    /// A window/keystroke association.
    public struct Association: Sendable, Equatable {
        /// Target window title (may be a regular expression).
        public var window: String
        /// Keystroke sequence to type into the window.
        public var keystrokeSequence: String

        /// Creates an association.
        public init(window: String, keystrokeSequence: String) {
            self.window = window
            self.keystrokeSequence = keystrokeSequence
        }
    }

    /// Whether auto-type is enabled (`nil` = inherit).
    public var enabled: Bool?
    /// Obfuscation method (spec value; 0 = none).
    public var dataTransferObfuscation: Int?
    /// Default keystroke sequence, if present.
    public var defaultSequence: String?
    /// Window-specific sequence overrides.
    public var associations: [Association] = []
    /// Unrecognized AutoType children, preserved structurally (D-06).
    public var unknownXml: [OpaqueNode] = []

    /// Creates empty auto-type settings.
    public init() {}
}

// MARK: - Times

/// Timestamp bookkeeping (spec Times).
public struct KdbxTimes: Sendable, Equatable {
    /// When the entry/group was created.
    public var creationTime: Date?
    /// Last modification time.
    public var lastModificationTime: Date?
    /// Last access time.
    public var lastAccessTime: Date?
    /// When the entry expires (meaningful with `expires`).
    public var expiryTime: Date?
    /// Whether expiry applies.
    public var expires: Bool?
    /// Usage/auto-type counter.
    public var usageCount: Int?
    /// When the entry last moved between groups.
    public var locationChanged: Date?

    /// Creates empty timestamps.
    public init() {}
}
