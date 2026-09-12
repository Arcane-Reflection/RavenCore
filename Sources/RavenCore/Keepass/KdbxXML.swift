import Foundation

/// KDBX XML layer: Foundation `XMLParser` (SAX) on read, hand-rolled writer on
/// output (iOS has no XMLDocument). Protected values ride the file-level
/// `KdbxProtectedStream`; the parser's callback order IS document order, which
/// is what keeps the running stream aligned.
///
/// Reader design: bottom-up frame stack. Every element opens a frame; when a
/// recognized container closes it assembles its payload from its direct child
/// frames (leaf text, child payloads, opaque subtrees). Unknown subtrees are
/// preserved structurally as `OpaqueNode` and replayed on write (D-06).
public enum KdbxXML {

    // MARK: - Reader

    /// SAX-driven assembler: builds a `KdbxDocument` bottom-up from parser
    /// callbacks (document order = callback order, which keeps the protected
    /// value stream aligned).
    public final class Reader: NSObject, XMLParserDelegate {
        /// Defense-in-depth nesting cap (02-REVIEW-FULL FI-05). Foundation's
        /// SAX parser is non-recursive, but opaque-subtree conversion and
        /// write-back recurse per level, and a hostile document needs ~10^5
        /// nested elements to overflow the stack — and the XML is only
        /// reachable after credential authentication. Legitimate KDBX nesting
        /// tops out around 6-8 levels (Times / History / CustomData), so 100
        /// leaves wide headroom while killing the whole recursion class at
        /// parse time.
        static let maxDepth = 100

        private let parser: XMLParser
        private let protectedStream: KdbxProtectedStream?
        private var rootFrame: Frame?
        private var stack: [Frame] = []
        private var parseError: KdbxError?

        /// The assembled document; non-`nil` after a successful `parse()`.
        public private(set) var document: KdbxDocument?

        init(data: Data, protectedStream: KdbxProtectedStream?) {
            self.parser = XMLParser(data: data)
            self.protectedStream = protectedStream
            super.init()
            parser.delegate = self
        }

        /// Runs the SAX parse and returns the assembled document.
        public func parse() throws -> KdbxDocument {
            guard parser.parse(), parseError == nil, let document else {
                throw parseError ?? KdbxError.corruptFile
            }
            return document
        }

        // MARK: Frame

        private final class Frame {
            var name: String
            var attributes: [String: String]
            var text = ""
            var children: [Frame] = []
            var built: Any?
            var opaqueNodes: [OpaqueNode] = []
            var isOpaque = false
            weak var parent: Frame?

            init(name: String, attributes: [String: String], parent: Frame?) {
                self.name = name
                self.attributes = attributes
                self.parent = parent
            }

            func childText(_ name: String) -> String? {
                children.first { $0.name == name }?.text.trimmingCharacters(in: .whitespacesAndNewlines)
            }

            func builtPayload<T>(_ type: T.Type, name: String) -> T? {
                children.first { $0.name == name }?.built as? T
            }

            func allBuilt<T>(_ type: T.Type, name: String) -> [T] {
                children.filter { $0.name == name }.compactMap { $0.built as? T }
            }
        }

        // MARK: XMLParserDelegate

        /// Opens a frame per element and enforces the depth cap (FI-05).
        public func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes attributeDict: [String: String] = [:]) {
            guard stack.count < Self.maxDepth else {
                parseError = KdbxError.corruptFile
                parser.abortParsing()
                return
            }
            let parent = stack.last
            let frame = Frame(name: name, attributes: attributeDict, parent: parent)
            frame.isOpaque = (parent?.isOpaque ?? false) || !isKnown(name, parent: parent?.name)
            stack.append(frame)
            if rootFrame == nil { rootFrame = frame }
        }

        /// Accumulates character data into the open frame.
        public func parser(_ parser: XMLParser, foundCharacters string: String) {
            stack.last?.text += string
        }

        /// Accumulates CDATA content into the open frame.
        public func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
            stack.last?.text += String(data: CDATABlock, encoding: .utf8) ?? ""
        }

        /// Closes the frame, attaches it to its parent, and assembles its payload.
        public func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            guard let frame = stack.last, frame.name == name else {
                parseError = KdbxError.corruptFile
                return
            }
            stack.removeLast()
            stack.last?.children.append(frame)

            if frame.isOpaque {
                stack.last?.opaqueNodes.append(Self.opaqueNode(from: frame))
                return
            }

            do {
                frame.built = try buildPayload(for: frame)
            } catch {
                parseError = (error as? KdbxError) ?? KdbxError.corruptFile
            }
        }

        /// Records a SAX-level failure as `corruptFile`.
        public func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) {
            self.parseError = KdbxError.corruptFile
        }

        // MARK: Known-element table

        private func isKnown(_ name: String, parent: String?) -> Bool {
            switch parent {
            case nil: return name == "KeePassFile"
            case "KeePassFile": return name == "Meta" || name == "Root"
            case "Meta": return Self.metaChildren.contains(name)
            case "Root": return name == "Group" || name == "DeletedObjects"
            case "Group": return Self.groupChildren.contains(name)
            case "Entry": return Self.entryChildren.contains(name)
            case "Times": return Self.timesChildren.contains(name)
            case "String", "Binary": return name == "Key" || name == "Value"
            case "MemoryProtection": return Self.memoryProtectionChildren.contains(name)
            case "CustomIcons": return name == "Icon"
            case "Icon": return name == "UUID" || name == "Data"
            case "CustomData": return name == "Item"
            case "Item": return name == "Key" || name == "Value" || name == "LastModificationTime"
            case "DeletedObjects": return name == "DeletedObject"
            case "DeletedObject": return name == "UUID" || name == "DeletionTime"
            case "AutoType": return Self.autoTypeChildren.contains(name)
            case "Association": return name == "Window" || name == "KeystrokeSequence"
            case "History": return name == "Entry"
            default: return false
            }
        }

        static let metaChildren: Set<String> = [
            "Generator", "DatabaseName", "DatabaseNameChanged", "DatabaseDescription",
            "DatabaseDescriptionChanged", "DefaultUserName", "DefaultUserNameChanged",
            "MaintenanceHistoryDays", "Color", "MasterKeyChanged", "MasterKeyChangeRec",
            "MasterKeyChangeForce", "MemoryProtection", "CustomIcons", "RecycleBinEnabled",
            "RecycleBinUUID", "RecycleBinChanged", "EntryTemplatesGroup",
            "EntryTemplatesGroupChanged", "HistoryMaxItems", "HistoryMaxSize",
            "LastSelectedGroup", "LastTopVisibleGroup", "CustomData", "SettingsChanged",
        ]
        static let groupChildren: Set<String> = [
            "UUID", "Name", "Notes", "IconID", "CustomIconUUID", "Times", "IsExpanded",
            "DefaultAutoTypeSequence", "EnableAutoType", "EnableSearching",
            "LastTopVisibleEntry", "CustomData", "Entry", "Group",
        ]
        static let entryChildren: Set<String> = [
            "UUID", "IconID", "CustomIconUUID", "ForegroundColor", "BackgroundColor",
            "OverrideURL", "Tags", "Times", "String", "Binary", "AutoType", "History", "CustomData",
        ]
        static let timesChildren: Set<String> = [
            "CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime",
            "Expires", "UsageCount", "LocationChanged",
        ]
        static let memoryProtectionChildren: Set<String> = [
            "ProtectTitle", "ProtectUserName", "ProtectPassword", "ProtectURL", "ProtectNotes",
        ]
        static let autoTypeChildren: Set<String> = [
            "Enabled", "DataTransferObfuscation", "DefaultSequence", "Association",
        ]

        // MARK: Payload assembly (bottom-up)

        private func buildPayload(for frame: Frame) throws -> Any? {
            switch frame.name {
            case "String":
                guard let key = frame.childText("Key"),
                      let valueFrame = frame.children.first(where: { $0.name == "Value" }) else {
                    throw KdbxError.corruptFile
                }
                var value = valueFrame.text
                let isProtected = (valueFrame.attributes["Protected"] ?? "False").caseInsensitiveCompare("True") == .orderedSame
                if isProtected, let stream = protectedStream {
                    // On-disk content is Base64 of the stream-encrypted bytes.
                    let encrypted = Data(base64Encoded: value) ?? Data()
                    value = String(data: stream.process(encrypted), encoding: .utf8) ?? ""
                }
                return KdbxString(key: key, value: value, protected: isProtected)

            case "Binary":
                guard let key = frame.childText("Key"),
                      let refText = frame.children.first(where: { $0.name == "Value" })?.attributes["Ref"],
                      let ref = Int(refText) else {
                    throw KdbxError.corruptFile
                }
                return KdbxBinaryReference(key: key, ref: ref)

            case "Times":
                var times = KdbxTimes()
                times.creationTime = frame.childText("CreationTime").flatMap(Self.parseDate)
                times.lastModificationTime = frame.childText("LastModificationTime").flatMap(Self.parseDate)
                times.lastAccessTime = frame.childText("LastAccessTime").flatMap(Self.parseDate)
                times.expiryTime = frame.childText("ExpiryTime").flatMap(Self.parseDate)
                times.expires = frame.childText("Expires").map { $0 == "True" }
                times.usageCount = frame.childText("UsageCount").flatMap(Int.init)
                times.locationChanged = frame.childText("LocationChanged").flatMap(Self.parseDate)
                return times

            case "MemoryProtection":
                var mp = KdbxMemoryProtection()
                mp.protectTitle = frame.childText("ProtectTitle").map { $0 == "True" }
                mp.protectUserName = frame.childText("ProtectUserName").map { $0 == "True" }
                mp.protectPassword = frame.childText("ProtectPassword").map { $0 == "True" }
                mp.protectURL = frame.childText("ProtectURL").map { $0 == "True" }
                mp.protectNotes = frame.childText("ProtectNotes").map { $0 == "True" }
                return mp

            case "CustomIcons":
                return frame.allBuilt(KdbxCustomIcon.self, name: "Icon")

            case "Icon":
                guard let uuidText = frame.childText("UUID"),
                      let uuid = Self.parseUUID(uuidText),
                      let dataText = frame.childText("Data"),
                      let data = Data(base64Encoded: dataText) else { return nil }
                return KdbxCustomIcon(uuid: uuid, pngData: data)

            case "CustomData":
                return frame.allBuilt((String, String).self, name: "Item")

            case "Item":
                guard let key = frame.childText("Key") else { return nil }
                return (key, frame.childText("Value") ?? "")

            case "DeletedObject":
                guard let uuid = frame.childText("UUID").flatMap(Self.parseUUID) else { return nil }
                return KdbxDeletedObject(uuid: uuid, deletionTime: frame.childText("DeletionTime").flatMap(Self.parseDate))

            case "DeletedObjects":
                return frame.allBuilt(KdbxDeletedObject.self, name: "DeletedObject")

            case "AutoType":
                var autoType = KdbxAutoType()
                autoType.enabled = frame.childText("Enabled").map { $0 == "True" }
                autoType.dataTransferObfuscation = frame.childText("DataTransferObfuscation").flatMap(Int.init)
                autoType.defaultSequence = frame.childText("DefaultSequence")
                for assoc in frame.children.filter({ $0.name == "Association" }) {
                    autoType.associations.append(
                        KdbxAutoType.Association(
                            window: assoc.childText("Window") ?? "",
                            keystrokeSequence: assoc.childText("KeystrokeSequence") ?? ""
                        )
                    )
                }
                autoType.unknownXml = frame.opaqueNodes
                return autoType

            case "Entry":
                return try buildEntry(frame)

            case "Group":
                return try buildGroup(frame)

            case "Meta":
                var meta = KdbxMeta()
                meta.generator = frame.childText("Generator")
                meta.databaseName = frame.childText("DatabaseName")
                meta.databaseNameChanged = frame.childText("DatabaseNameChanged").flatMap(Self.parseDate)
                meta.memoryProtection = frame.builtPayload(KdbxMemoryProtection.self, name: "MemoryProtection") ?? KdbxMemoryProtection()
                meta.customIcons = frame.builtPayload([KdbxCustomIcon].self, name: "CustomIcons") ?? []
                meta.recycleBinEnabled = frame.childText("RecycleBinEnabled").map { $0 == "True" }
                meta.recycleBinUUID = frame.childText("RecycleBinUUID").flatMap(Self.parseUUID)
                meta.recycleBinChanged = frame.childText("RecycleBinChanged").flatMap(Self.parseDate)
                meta.entryTemplatesGroup = frame.childText("EntryTemplatesGroup").flatMap(Self.parseUUID)
                meta.historyMaxItems = frame.childText("HistoryMaxItems").flatMap(Int.init)
                meta.historyMaxSize = frame.childText("HistoryMaxSize").flatMap(Int.init)
                meta.settingsChanged = frame.childText("SettingsChanged").flatMap(Self.parseDate)
                let items = frame.builtPayload([(String, String)].self, name: "CustomData") ?? []
                for (k, v) in items { meta.customData[k] = v }
                meta.unknownXml = frame.opaqueNodes
                meta.unknownAttributes = unknownAttributes(of: frame)
                return meta

            case "Root":
                let group = frame.builtPayload(KdbxGroup.self, name: "Group")
                let deleted = frame.builtPayload([KdbxDeletedObject].self, name: "DeletedObjects") ?? []
                return (group, deleted)

            case "KeePassFile":
                var document = KdbxDocument()
                document.meta = frame.builtPayload(KdbxMeta.self, name: "Meta") ?? KdbxMeta()
                if let (group, deleted) = frame.builtPayload((KdbxGroup, [KdbxDeletedObject]).self, name: "Root") {
                    document.root = group
                    document.deletedObjects = deleted
                }
                document.unknownAttributes = unknownAttributes(of: frame)
                self.document = document
                return nil

            default:
                // Recognized leaf (plain text under a known parent).
                return nil
            }
        }

        private func buildEntry(_ frame: Frame) throws -> KdbxEntry {
            var entry = KdbxEntry()
            applyUnknownAttributes(frame, into: &entry)
            for child in frame.children {
                let text = child.text.trimmingCharacters(in: .whitespacesAndNewlines)
                switch child.name {
                case "UUID":
                    // Identity is never reinvented (02-REVIEW-FULL FI-09): a
                    // present-but-corrupt UUID element is a corrupt file, not
                    // grounds for a fresh random identity. Optional UUID refs
                    // (CustomIconUUID etc.) stay lenient — only identity
                    // hard-fails.
                    guard let uuid = Self.parseUUID(text) else { throw KdbxError.corruptFile }
                    entry.uuid = uuid
                case "IconID": entry.iconId = UInt64(text)
                case "CustomIconUUID": entry.customIconUUID = Self.parseUUID(text)
                case "ForegroundColor": entry.foregroundColor = text
                case "BackgroundColor": entry.backgroundColor = text
                case "OverrideURL": entry.overrideURL = text
                case "Tags": entry.tags = text
                case "Times": entry.times = child.built as? KdbxTimes
                case "String":
                    if let s = child.built as? KdbxString { entry.strings.append(s) }
                case "Binary":
                    if let b = child.built as? KdbxBinaryReference { entry.binaries.append(b) }
                case "AutoType": entry.autoType = child.built as? KdbxAutoType
                case "History":
                    entry.history = child.children.filter { $0.name == "Entry" }.compactMap { $0.built as? KdbxEntry }
                case "CustomData":
                    let items = (child.built as? [(String, String)]) ?? []
                    for (k, v) in items { entry.customData[k] = v }
                default: break
                }
            }
            entry.unknownXml = frame.opaqueNodes
            return entry
        }

        private func buildGroup(_ frame: Frame) throws -> KdbxGroup {
            var group = KdbxGroup(name: "")
            applyUnknownAttributes(frame, into: &group)
            for child in frame.children {
                let text = child.text.trimmingCharacters(in: .whitespacesAndNewlines)
                switch child.name {
                case "UUID":
                    // Same identity rule as entries (FI-09).
                    guard let uuid = Self.parseUUID(text) else { throw KdbxError.corruptFile }
                    group.uuid = uuid
                case "Name": group.name = text
                case "Notes": group.notes = text
                case "CustomIconUUID": group.customIconUUID = Self.parseUUID(text)
                case "Times": group.times = child.built as? KdbxTimes
                case "IsExpanded": group.isExpanded = text == "True"
                case "DefaultAutoTypeSequence": group.defaultAutoTypeSequence = text
                case "EnableAutoType": group.enableAutoType = text == "True"
                case "EnableSearching": group.enableSearching = text == "True"
                case "LastTopVisibleEntry": group.lastTopVisibleEntry = Self.parseUUID(text)
                case "CustomData":
                    let items = (child.built as? [(String, String)]) ?? []
                    for (k, v) in items { group.customData[k] = v }
                case "Entry":
                    if let entry = child.built as? KdbxEntry { group.entries.append(entry) }
                case "Group":
                    if let sub = child.built as? KdbxGroup { group.groups.append(sub) }
                default: break
                }
            }
            group.unknownXml = frame.opaqueNodes
            return group
        }

        private func applyUnknownAttributes(_ frame: Frame, into entry: inout KdbxEntry) {
            entry.unknownAttributes = unknownAttributes(of: frame)
        }

        private func applyUnknownAttributes(_ frame: Frame, into group: inout KdbxGroup) {
            group.unknownAttributes = unknownAttributes(of: frame)
        }

        private func unknownAttributes(of frame: Frame) -> UnknownAttributes {
            frame.attributes
                .filter { $0.key != "Protected" }
                .sorted { $0.key < $1.key }
                .map { OpaqueAttribute(name: $0.key, value: $0.value) }
        }

        // MARK: Opaque subtree conversion

        private static func opaqueNode(from frame: Frame) -> OpaqueNode {
            OpaqueNode(
                name: frame.name,
                attributes: frame.attributes.sorted { $0.key < $1.key }.map { OpaqueAttribute(name: $0.key, value: $0.value) },
                text: frame.text,
                children: frame.children.map { opaqueNode(from: $0) }
            )
        }

        // MARK: Value parsing

        static func parseUUID(_ text: String) -> UUID? {
            guard let data = Data(base64Encoded: text) else { return nil }
            return UUID(data: data)
        }

        static func parseDate(_ text: String) -> Date? {
            // KDBX 4: ISO 8601 ("2026-09-11T00:00:00Z"); KDBX 3.1: Base64 of
            // Int64-LE seconds since 0001-01-01.
            if let date = try? Self.isoFormat.parse(text) { return date }
            if let data = Data(base64Encoded: text), data.count == 8 {
                var reader = ByteReader(data)
                if let seconds = try? reader.readUInt64() {
                    return Date(timeIntervalSinceReferenceDate: TimeInterval(Int64(bitPattern: seconds) - 62_135_596_800))
                }
            }
            return nil
        }

        /// Value-type strategy (Sendable): identical internet-date-time
        /// grammar to the `ISO8601DateFormatter` it replaced, but no per-call
        /// allocation — the old computed formatter was re-created for every
        /// date parsed, thousands of allocations on a 10k-entry open, purely
        /// for thread safety (02-REVIEW-FULL FI-09). A value type needs no
        /// such posture.
        private static let isoFormat = Date.ISO8601FormatStyle()
    }

    // MARK: - Writer

    /// Hand-rolled XML writer: UTF-8, no BOM, canonical element order.
    /// Protected values are encrypted through the protection stream in
    /// document order — the write traversal IS the document order.
    public final class Writer {
        private var out = ""
        private let protectedStream: KdbxProtectedStream?

        /// Value-type strategy, shared instance (FI-09 — see the reader's
        /// `isoFormat` note). Output is identical to the previous
        /// per-call `ISO8601DateFormatter`: second-precision UTC ("…T…Z").
        private static let timeFormat = Date.ISO8601FormatStyle()

        /// Creates a writer. `protectedStream` encrypts protected values in
        /// document order — pass the same stream instance used for the whole file.
        public init(protectedStream: KdbxProtectedStream?) {
            self.protectedStream = protectedStream
        }

        /// Serializes the document to canonical UTF-8 XML (no BOM).
        public func serialize(_ document: KdbxDocument) -> Data {
            out = ""
            writeRaw("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>")
            open("KeePassFile")
            writeAttributes(document.unknownAttributes)
            writeMeta(document.meta)
            writeRoot(document)
            close("KeePassFile")
            return Data(out.utf8)
        }

        private func writeMeta(_ meta: KdbxMeta) {
            open("Meta")
            leaf("Generator", meta.generator)
            if let v = meta.databaseName { leaf("DatabaseName", v) }
            if let v = meta.databaseNameChanged { leaf("DatabaseNameChanged", Self.timeFormat.format(v)) }
            open("MemoryProtection")
            if let v = meta.memoryProtection.protectTitle { leaf("ProtectTitle", v ? "True" : "False") }
            if let v = meta.memoryProtection.protectUserName { leaf("ProtectUserName", v ? "True" : "False") }
            if let v = meta.memoryProtection.protectPassword { leaf("ProtectPassword", v ? "True" : "False") }
            if let v = meta.memoryProtection.protectURL { leaf("ProtectURL", v ? "True" : "False") }
            if let v = meta.memoryProtection.protectNotes { leaf("ProtectNotes", v ? "True" : "False") }
            close("MemoryProtection")
            if !meta.customIcons.isEmpty {
                open("CustomIcons")
                for icon in meta.customIcons {
                    open("Icon")
                    leaf("UUID", base64(icon.uuid.data))
                    leaf("Data", base64(icon.pngData))
                    close("Icon")
                }
                close("CustomIcons")
            }
            if let v = meta.recycleBinEnabled { leaf("RecycleBinEnabled", v ? "True" : "False") }
            if let v = meta.recycleBinUUID { leaf("RecycleBinUUID", base64(v.data)) }
            if let v = meta.recycleBinChanged { leaf("RecycleBinChanged", Self.timeFormat.format(v)) }
            if let v = meta.entryTemplatesGroup { leaf("EntryTemplatesGroup", base64(v.data)) }
            if let v = meta.historyMaxItems { leaf("HistoryMaxItems", String(v)) }
            if let v = meta.historyMaxSize { leaf("HistoryMaxSize", String(v)) }
            if !meta.customData.isEmpty {
                open("CustomData")
                for (k, v) in meta.customData.sorted(by: { $0.key < $1.key }) {
                    open("Item")
                    leaf("Key", k)
                    leaf("Value", v)
                    close("Item")
                }
                close("CustomData")
            }
            if let v = meta.settingsChanged { leaf("SettingsChanged", Self.timeFormat.format(v)) }
            for node in meta.unknownXml { writeOpaque(node) }
            close("Meta")
        }

        private func writeRoot(_ document: KdbxDocument) {
            open("Root")
            writeGroup(document.root)
            if !document.deletedObjects.isEmpty {
                open("DeletedObjects")
                for deleted in document.deletedObjects {
                    open("DeletedObject")
                    leaf("UUID", base64(deleted.uuid.data))
                    if let t = deleted.deletionTime { leaf("DeletionTime", Self.timeFormat.format(t)) }
                    close("DeletedObject")
                }
                close("DeletedObjects")
            }
            close("Root")
        }

        private func writeGroup(_ group: KdbxGroup) {
            open("Group")
            writeAttributes(group.unknownAttributes)
            leaf("UUID", base64(group.uuid.data))
            leaf("Name", group.name)
            if let v = group.notes { leaf("Notes", v) }
            if let v = group.customIconUUID { leaf("CustomIconUUID", base64(v.data)) }
            if let t = group.times { writeTimes(t) }
            if let v = group.isExpanded { leaf("IsExpanded", v ? "True" : "False") }
            if let v = group.defaultAutoTypeSequence { leaf("DefaultAutoTypeSequence", v) }
            if let v = group.enableAutoType { leaf("EnableAutoType", v ? "True" : "False") }
            if let v = group.enableSearching { leaf("EnableSearching", v ? "True" : "False") }
            if let v = group.lastTopVisibleEntry { leaf("LastTopVisibleEntry", base64(v.data)) }
            writeCustomData(group.customData)
            for entry in group.entries { writeEntry(entry) }
            for sub in group.groups { writeGroup(sub) }
            for node in group.unknownXml { writeOpaque(node) }
            close("Group")
        }

        private func writeEntry(_ entry: KdbxEntry) {
            open("Entry")
            writeAttributes(entry.unknownAttributes)
            leaf("UUID", base64(entry.uuid.data))
            if let v = entry.iconId { leaf("IconID", String(v)) }
            if let v = entry.customIconUUID { leaf("CustomIconUUID", base64(v.data)) }
            if let v = entry.foregroundColor { leaf("ForegroundColor", v) }
            if let v = entry.backgroundColor { leaf("BackgroundColor", v) }
            if let v = entry.overrideURL { leaf("OverrideURL", v) }
            if let v = entry.tags { leaf("Tags", v) }
            if let t = entry.times { writeTimes(t) }
            for s in entry.strings {
                open("String")
                leaf("Key", s.key)
                if s.protected {
                    let encrypted = protectedStream?.process(Data(s.value.utf8)) ?? Data(s.value.utf8)
                    leafProtectedValue(base64(encrypted))
                } else {
                    leaf("Value", s.value)
                }
                close("String")
            }
            for b in entry.binaries {
                open("Binary")
                leaf("Key", b.key)
                writeRaw("<Value Ref=\"\(b.ref)\" />")
                close("Binary")
            }
            if let a = entry.autoType { writeAutoType(a) }
            if !entry.history.isEmpty {
                open("History")
                for historic in entry.history { writeEntry(historic) }
                close("History")
            }
            writeCustomData(entry.customData)
            for node in entry.unknownXml { writeOpaque(node) }
            close("Entry")
        }

        private func writeTimes(_ times: KdbxTimes) {
            open("Times")
            if let v = times.creationTime { leaf("CreationTime", Self.timeFormat.format(v)) }
            if let v = times.lastModificationTime { leaf("LastModificationTime", Self.timeFormat.format(v)) }
            if let v = times.lastAccessTime { leaf("LastAccessTime", Self.timeFormat.format(v)) }
            if let v = times.expiryTime { leaf("ExpiryTime", Self.timeFormat.format(v)) }
            if let v = times.expires { leaf("Expires", v ? "True" : "False") }
            if let v = times.usageCount { leaf("UsageCount", String(v)) }
            if let v = times.locationChanged { leaf("LocationChanged", Self.timeFormat.format(v)) }
            close("Times")
        }

        private func writeAutoType(_ autoType: KdbxAutoType) {
            open("AutoType")
            if let v = autoType.enabled { leaf("Enabled", v ? "True" : "False") }
            if let v = autoType.dataTransferObfuscation { leaf("DataTransferObfuscation", String(v)) }
            if let v = autoType.defaultSequence { leaf("DefaultSequence", v) }
            for assoc in autoType.associations {
                open("Association")
                leaf("Window", assoc.window)
                leaf("KeystrokeSequence", assoc.keystrokeSequence)
                close("Association")
            }
            for node in autoType.unknownXml { writeOpaque(node) }
            close("AutoType")
        }

        private func writeCustomData(_ customData: [String: String]) {
            guard !customData.isEmpty else { return }
            open("CustomData")
            for (k, v) in customData.sorted(by: { $0.key < $1.key }) {
                open("Item")
                leaf("Key", k)
                leaf("Value", v)
                close("Item")
            }
            close("CustomData")
        }

        private func writeOpaque(_ node: OpaqueNode) {
            open(node.name)
            writeAttributes(node.attributes)
            if !node.text.isEmpty { writeEscaped(node.text) }
            for child in node.children { writeOpaque(child) }
            close(node.name)
        }

        // MARK: Low-level emission

        private func writeAttributes(_ attributes: UnknownAttributes) {
            guard !attributes.isEmpty, pending != nil else { return }
            for attr in attributes {
                pending?.attrs += " \(attr.name)=\"\(escape(attr.value, attribute: true))\""
            }
        }

        /// The element currently being opened whose `>` is not yet emitted —
        /// attributes can still be added to it.
        private var pending: (name: String, attrs: String)?

        private func flushPending() {
            guard let tag = pending else { return }
            out += "<\(tag.name)\(tag.attrs)>"
            pending = nil
        }

        private func open(_ tag: String) {
            flushPending()
            pending = (tag, "")
        }

        private func close(_ tag: String) {
            flushPending()
            out += "</\(tag)>"
        }

        private func leaf(_ tag: String, _ value: String?) {
            flushPending()
            if let value {
                out += "<\(tag)>\(escape(value, attribute: false))</\(tag)>"
            }
        }

        private func leafProtectedValue(_ base64Value: String) {
            flushPending()
            out += "<Value Protected=\"True\">\(base64Value)</Value>"
        }

        private func writeEscaped(_ text: String) {
            flushPending()
            out += escape(text, attribute: false)
        }

        private func writeRaw(_ raw: String) {
            flushPending()
            out += raw
        }

        private func base64(_ data: Data) -> String {
            data.base64EncodedString()
        }

        private func escape(_ value: String, attribute: Bool) -> String {
            var escaped = value
            escaped = escaped
                .replacingOccurrences(of: "&", with: "&amp;")
                .replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;")
            if attribute {
                escaped = escaped
                    .replacingOccurrences(of: "\"", with: "&quot;")
                    .replacingOccurrences(of: "'", with: "&apos;")
            }
            return escaped
        }
    }
}
