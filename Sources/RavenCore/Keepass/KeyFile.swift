import Foundation

/// KeePass key file support (CORE-06). Read semantics mirror KeePassXC's
/// `FileKey.cpp`: content negotiation in a fixed order, extension-agnostic.
///
/// Formats, in negotiation order:
/// 1. XML v1.0 (`.key`): `Meta/Version` starts with "1.0", `Key/Data` = Base64
/// 2. XML v2.0 (`.keyx`): `Version == 2.0`, `Data` = hex with a `Hash`
///    attribute = first 4 bytes of SHA-256(raw key), uppercase hex
/// 3. Exactly 32 raw bytes → used directly
/// 4. Exactly 64 hex characters → decoded to 32 bytes
/// 5. Anything else → SHA-256 of the full file content (arbitrary files)
public enum KdbxKeyFile {

    /// Extracts the 32-byte key from any supported key-file flavor:
    /// XML v1.0/v2.0, raw binary, hex text, or (fallback) SHA-256 of the file.
    public static func load(data: Data) throws -> Data {
        // 1/2: XML formats are authoritative — a file that declares itself a
        // key file must not silently fall through to the hashed fallback
        // (KeePassXC FileKey.cpp: non-empty xmlError aborts the load).
        if let text = String(data: data, encoding: .utf8), text.contains("<KeyFile") {
            return try loadXML(Data(text.utf8))
        }
        // 3: fixed 32-byte binary
        if data.count == 32 { return data }
        // 4: fixed 64-char hex (one line, no spaces)
        if data.count == 64, let decoded = Data(hex: String(data: data, encoding: .ascii) ?? "") {
            return decoded
        }
        // 5: hashed fallback — arbitrary files
        return Hmac.sha256(data)
    }

    /// Generates a key file in the KeePass XML v2.0 layout: 32 random bytes,
    /// hex payload (pretty-printed), `Hash` = SHA-256(key)[0..4] uppercase.
    public static func generate() throws -> Data {
        let raw = SecureRandom.bytes(count: 32)
        let hashPrefix = Hmac.sha256(raw).prefix(4).map { String(format: "%02X", $0) }.joined()
        let hex = raw.map { String(format: "%02X", $0) }.joined()

        var xml = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
        xml += "<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data Hash=\"\(hashPrefix)\">\n"
        var index = hex.startIndex
        while index < hex.endIndex {
            let end = hex.index(index, offsetBy: 8, limitedBy: hex.endIndex) ?? hex.endIndex
            xml += "\t\t\t" + hex[index..<end] + "\n"
            index = end
        }
        xml += "\t\t</Data>\n\t</Key>\n</KeyFile>\n"
        return Data(xml.utf8)
    }

    // MARK: - XML parsing (SAX, same layer as the kdbx XML reader)

    private static func loadXML(_ data: Data) throws -> Data {
        final class Delegate: NSObject, XMLParserDelegate {
            var path: [String] = []
            var version = ""
            var hashAttribute = ""
            var dataText = ""
            var currentText = ""

            func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes attributeDict: [String: String] = [:]) {
                path.append(name)
                currentText = ""
                if name == "Data" {
                    hashAttribute = attributeDict["Hash"] ?? ""
                }
            }

            func parser(_ parser: XMLParser, foundCharacters string: String) {
                currentText += string
            }

            func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
                let text = currentText.trimmingCharacters(in: .whitespacesAndNewlines)
                switch name {
                case "Version": version = text
                case "Data": dataText = text
                default: break
                }
                path.removeLast()
                currentText = ""
            }
        }

        let delegate = Delegate()
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        guard parser.parse(), !delegate.dataText.isEmpty else {
            throw KdbxError.keyFileCorrupt
        }

        let cleaned = delegate.dataText
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\t", with: "")

        if delegate.version.hasPrefix("1.0") {
            guard let raw = Data(base64Encoded: cleaned), !raw.isEmpty else {
                throw KdbxError.keyFileCorrupt
            }
            return raw
        }
        if delegate.version == "2.0" {
            guard let raw = Data(hex: cleaned), !raw.isEmpty else {
                throw KdbxError.keyFileCorrupt
            }
            let expected = Hmac.sha256(raw).prefix(4).map { String(format: "%02X", $0) }.joined()
            guard delegate.hashAttribute.uppercased() == expected else {
                throw KdbxError.keyFileCorrupt
            }
            return raw
        }
        throw KdbxError.unsupportedKeyFile
    }
}

private extension Data {
    /// Strict hex decoding (even length, valid hex digits).
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
