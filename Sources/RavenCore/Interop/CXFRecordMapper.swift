import CryptoKit
import Foundation

/// CXF (Credential Exchange Format) → `RecordPayload` mapping (06-CONTEXT
/// D-11, plan Task 3): a pure engine mapper over a neutral mirror of the
/// CXF decoded shape. The mirror exists because the engine (MIT core) builds
/// and tests on macOS where the iOS-26-only `ASImportable*` types are
/// unavailable — the app-side `CXFImportCoordinator` converts the system
/// types 1:1 into these mirrors, and this mapper owns everything semantic:
/// per-item validation, honest Added/Skipped accounting (the E14 pattern —
/// count and name the loss, never abort the batch), and the D-07 verbatim
/// `totpSecret` storage semantics.
///
/// ZERO vault mutation happens here — the mapper returns data; the merge
/// into the unlocked vault is the app layer's gated, all-or-nothing step.
public enum CXFRecordMapper {

    // MARK: - Neutral mirror of the CXF decoded shape

    /// One source account (mirrors `ASImportableAccount`'s import-relevant
    /// fields; the wire names live in the Codable conformance below).
    public struct SourceAccount: Sendable, Equatable {
        public var userName: String
        public var items: [SourceItem]

        public init(userName: String, items: [SourceItem]) {
            self.userName = userName
            self.items = items
        }
    }

    /// One source item (mirrors `ASImportableItem`): display title plus the
    /// scope URLs the credentials belong to and the credential list.
    public struct SourceItem: Sendable, Equatable {
        public var title: String
        public var subtitle: String?
        public var urls: [String]
        public var credentials: [SourceCredential]

        public init(title: String, subtitle: String? = nil, urls: [String] = [],
                    credentials: [SourceCredential]) {
            self.title = title
            self.subtitle = subtitle
            self.urls = urls
            self.credentials = credentials
        }
    }

    /// The credential kinds RavenVault understands plus the honest
    /// "unsupported" bucket (note/creditCard/… count as named skips).
    public enum SourceCredential: Sendable, Equatable {
        case basicAuthentication(userName: String?, password: String?)
        /// `algorithm` is the raw wire spelling ("sha1"|"sha256"|"sha512");
        /// mapping to the engine's `TOTPGenerator.Algorithm` happens in
        /// `totpSecret`, where an unknown spelling is a skip, not a guess.
        case totp(
            secret: Data, period: Int, digits: Int,
            userName: String?, algorithm: String, issuer: String?)
        case passkey(
            credentialID: Data, rpID: String, userName: String,
            userHandle: Data, key: Data)
        /// Any kind RavenVault does not store — carried with its wire type
        /// name so the report can name exactly what was left behind.
        case unsupported(kind: String)
    }

    // MARK: - Typed decode of the CXF JSON shape

    public enum CXFDecodeError: Error, Equatable {
        /// The payload is not the CXF shape at all — the caller treats this
        /// as the E21 "damaged transfer" failure with ZERO vault mutation.
        case malformedPayload
    }

    /// Decodes the CXF JSON payload into source accounts. The payload root
    /// is the exported-credential document (`{"accounts": […], …}` — the
    /// pinned `ASExportedCredentialData` shape; its `version`/`timestamp`/
    /// exporter fields carry no import value and are tolerated as absent).
    /// The decoder is strictly typed and local (D-05/D-11: decode happens on
    /// this device, no network anywhere). Dates ride `.secondsSince1970`,
    /// the documented CXF strategy.
    public static func decode(_ data: Data) throws -> [SourceAccount] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        do {
            return try decoder.decode(ExportedPayload.self, from: data).accounts
        } catch {
            throw CXFDecodeError.malformedPayload
        }
    }

    /// The payload root mirror.
    private struct ExportedPayload: Codable {
        let accounts: [SourceAccount]
    }

    // MARK: - Honest mapping report

    /// One mapped record, ready for `VaultService.add` (the session merge
    /// supplies level/tags/folder policy exactly as CSV import does).
    public struct Entry: Sendable, Equatable {
        public let type: RecordType
        public let payload: RecordPayload

        public init(type: RecordType, payload: RecordPayload) {
            self.type = type
            self.payload = payload
        }
    }

    /// One named loss. `reason` is a stable key-side identifier the report
    /// UI renders through `interop.transfer.skip.*` copy — never raw
    /// credential content (T-06-13 posture).
    public struct Skip: Sendable, Equatable {
        public let title: String
        public let reason: String

        public init(title: String, reason: String) {
            self.title = title
            self.reason = reason
        }
    }

    /// The honest Added/Skipped result (E14 pattern).
    public struct Report: Sendable, Equatable {
        public let added: [Entry]
        public let skipped: [Skip]

        public init(added: [Entry], skipped: [Skip]) {
            self.added = added
            self.skipped = skipped
        }
    }

    /// Maps every source account into entries + named skips. An item's
    /// basic-authentication credential is the record spine; a sibling TOTP
    /// attaches to it (the way one password entry carries its generator
    /// secret) unless the spine already carries one — a second sibling TOTP
    /// is a named `duplicateTotp` skip, never a silent overwrite — a passkey
    /// becomes its own record, everything else is named and counted. An item
    /// with no credentials at all is itself a named loss.
    public static func map(accounts: [SourceAccount]) -> Report {
        var added: [Entry] = []
        var skipped: [Skip] = []

        for account in accounts {
            for item in account.items {
                let title = displayTitle(item: item, account: account)
                guard !item.credentials.isEmpty else {
                    skipped.append(Skip(title: title, reason: "empty"))
                    continue
                }
                // Two passes so the TOTP attach decision is ORDER-INDEPENDENT
                // (fifth-pass review: [totp, basic] used to produce a
                // standalone TOTP record plus a bare password, while
                // [basic, totp] combined them — same manifest, two results).
                // Pass 1 creates the structural credentials in file order and
                // collects the item's generator secrets; pass 2 attaches them
                // to the item's spine (its first password record).
                var spineIndex: Int?
                var pendingTOTPs: [(composed: String, userName: String)] = []
                for credential in item.credentials {
                    switch credential {
                    case .basicAuthentication(let userName, let password):
                        if (userName ?? "").isEmpty && (password ?? "").isEmpty {
                            skipped.append(Skip(title: title, reason: "empty"))
                            continue
                        }
                        if spineIndex == nil { spineIndex = added.count }
                        added.append(Entry(
                            type: .password,
                            payload: RecordPayload(
                                title: title,
                                username: userName ?? "",
                                password: password ?? "",
                                url: item.urls.first)))
                    case .totp(let secret, let period, let digits,
                                let userName, let algorithm, let issuer):
                        if let composed = totpSecret(
                            secret: secret, period: period, digits: digits,
                            userName: userName ?? item.title,
                            algorithm: algorithm, issuer: issuer) {
                            // The standalone (no-spine) shape keeps this
                            // credential's own username, so the pair rides
                            // through collection.
                            pendingTOTPs.append((composed, userName ?? ""))
                        } else {
                            skipped.append(Skip(title: title, reason: "unreadableTotp"))
                        }
                    case .passkey(let credentialID, let rpID, let userName,
                                  let userHandle, let key):
                        if let credential = passkeyCredential(
                            credentialID: credentialID, rpID: rpID,
                            userName: userName, userHandle: userHandle, key: key) {
                            var payload = RecordPayload(
                                title: title,
                                username: userName,
                                // Synthesized origin so the record joins the
                                // D-01 offer scope (matching what the
                                // extension's registration persists).
                                url: item.urls.first ?? "https://\(rpID)")
                            payload.passkey = credential
                            added.append(Entry(type: .password, payload: payload))
                        } else {
                            skipped.append(Skip(title: title, reason: "unreadablePasskey"))
                        }
                    case .unsupported(let kind):
                        skipped.append(Skip(title: title, reason: "unsupported.\(kind)"))
                    }
                }
                // Pass 2 — attach the collected TOTPs: the first fills the
                // spine (or becomes a standalone `.totp` record when the item
                // has no password at all — the no-spine shape); the rest are
                // named duplicateTotp skips, never silent overwrites.
                for pending in pendingTOTPs {
                    if let index = spineIndex {
                        if added[index].payload.totpSecret != nil {
                            // E14 honesty (06 review WR-03): the spine
                            // already carries a generator secret — the
                            // sibling TOTP is a NAMED loss, never a
                            // silent overwrite.
                            skipped.append(Skip(title: title, reason: "duplicateTotp"))
                        } else {
                            var payload = added[index].payload
                            payload.totpSecret = pending.composed
                            added[index] = Entry(type: added[index].type, payload: payload)
                        }
                    } else {
                        added.append(Entry(
                            type: .totp,
                            payload: RecordPayload(
                                title: title,
                                username: pending.userName,
                                totpSecret: pending.composed,
                                url: item.urls.first)))
                    }
                }
            }
        }
        return Report(added: added, skipped: skipped)
    }

    /// D-07 verbatim storage semantics (the 06-02 decision): a bare secret
    /// when every generation parameter sits at the RFC 6238 default and no
    /// issuer was carried; otherwise the full `otpauth://` URI composed from
    /// the actual parameters — the same grammar `OTPAuthURIParser` reads
    /// back. An unknown algorithm spelling (or an empty secret) yields nil —
    /// a named skip, never a silently wrong generator.
    public static func totpSecret(
        secret: Data, period: Int, digits: Int,
        userName: String, algorithm: String, issuer: String?
    ) -> String? {
        guard !secret.isEmpty,
              let parsed = TOTPGenerator.Algorithm(rawValue: algorithm.uppercased())
        else { return nil }
        let encoded = Base32.encode([UInt8](secret))
        let isDefault = parsed == .sha1
            && digits == TOTPGenerator.defaultDigits
            && period == TOTPGenerator.defaultPeriod
            && (issuer ?? "").isEmpty
        if isDefault {
            return encoded
        }
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = "totp"
        let label: String
        if let issuer, !issuer.isEmpty {
            label = "\(issuer):\(userName)"
        } else {
            label = userName
        }
        components.path = "/" + label
        var items: [URLQueryItem] = [URLQueryItem(name: "secret", value: encoded)]
        if let issuer, !issuer.isEmpty {
            items.append(URLQueryItem(name: "issuer", value: issuer))
        }
        if parsed != .sha1 {
            items.append(URLQueryItem(name: "algorithm", value: parsed.rawValue))
        }
        if digits != TOTPGenerator.defaultDigits {
            items.append(URLQueryItem(name: "digits", value: String(digits)))
        }
        if period != TOTPGenerator.defaultPeriod {
            items.append(URLQueryItem(name: "period", value: String(period)))
        }
        components.queryItems = items
        return components.string
    }

    /// Converts CXF passkey material into the KeePassXC-compatible
    /// `PasskeyCredential` (D-09/D-10): credential ID and user handle are
    /// base64url-encoded verbatim (the KPEX storage form), and the raw
    /// private-key bytes are normalized to the PKCS#8 PEM the codec stores.
    /// Apple's CXF `key` field carries the SEC1 x9.63 form (`0x04 ‖ x ‖ y ‖
    /// priv`); the DER/raw spellings are tried defensively so a future wire
    /// variant still imports. Nothing renderable survives here but the
    /// stored PEM (T-06-13: the key exists only in this conversion).
    public static func passkeyCredential(
        credentialID: Data, rpID: String, userName: String,
        userHandle: Data, key: Data
    ) -> PasskeyCredential? {
        guard !credentialID.isEmpty, !userHandle.isEmpty, !rpID.isEmpty,
              !key.isEmpty else { return nil }
        let privateKey: P256.Signing.PrivateKey?
        if let key = try? P256.Signing.PrivateKey(x963Representation: key) {
            privateKey = key
        } else if let key = try? P256.Signing.PrivateKey(
            derRepresentation: key) {
            privateKey = key
        } else if let key = try? P256.Signing.PrivateKey(rawRepresentation: key) {
            privateKey = key
        } else {
            privateKey = nil
        }
        guard let privateKey else { return nil }
        return PasskeyCredential(
            username: userName,
            rpID: rpID,
            credentialID: KdbxPasskey.base64URLEncode(credentialID),
            userHandle: KdbxPasskey.base64URLEncode(userHandle),
            privateKeyPEM: privateKey.pemRepresentation,
            // Fresh CXF credentials are backup-capable and start backed up —
            // the same posture the extension's registration persists.
            backupEligibility: true,
            backupState: true)
    }

    /// Item display title with honest fallbacks (subtitle, then the account
    /// user name) — an import never fabricates an empty title.
    private static func displayTitle(item: SourceItem, account: SourceAccount) -> String {
        let candidates = [item.title, item.subtitle ?? "", account.userName]
        for candidate in candidates where !candidate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return candidate
        }
        return "Imported item"
    }
}

// MARK: - Codable (the pinned CXF wire shape)

/// The wire spelling was pinned empirically from the iOS 26.5 SDK's real
/// `ASExportedCredentialData` Codable implementation (2026-09-13): the
/// credential discriminator is `"type"` with values `basic-auth` / `totp` /
/// `passkey` / `note` / `credit-card` / …, accounts use `"username"`, items
/// carry `"scope".urls`, passkeys use `"rpId"`/`"credentialId"`, and Data
/// fields are standard base64. Nil fields are tolerated as absent.
extension CXFRecordMapper.SourceAccount: Codable {
    private enum CodingKeys: String, CodingKey {
        case userName = "username"
        case items
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        userName = try container.decodeIfPresent(String.self, forKey: .userName) ?? ""
        items = try container.decodeIfPresent([CXFRecordMapper.SourceItem].self, forKey: .items) ?? []
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(userName, forKey: .userName)
        try container.encode(items, forKey: .items)
    }
}

extension CXFRecordMapper.SourceItem: Codable {
    private enum CodingKeys: String, CodingKey {
        case title, subtitle
        case scope
        case credentials
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        title = try container.decodeIfPresent(String.self, forKey: .title) ?? ""
        subtitle = try container.decodeIfPresent(String.self, forKey: .subtitle)
        if let scope = try container.decodeIfPresent(Scope.self, forKey: .scope) {
            urls = scope.urls
        } else {
            urls = []
        }
        credentials = try container.decode(
            [CXFRecordMapper.SourceCredential].self, forKey: .credentials)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(title, forKey: .title)
        try container.encodeIfPresent(subtitle, forKey: .subtitle)
        try container.encode(Scope(urls: urls), forKey: .scope)
        try container.encode(credentials, forKey: .credentials)
    }

    /// The scope mirror (`ASImportableCredentialScope.urls`).
    struct Scope: Codable, Sendable, Equatable {
        var urls: [String]
    }
}

extension CXFRecordMapper.SourceCredential: Codable {
    private enum CodingKeys: String, CodingKey {
        case type
        case userName = "username"
        case password
        case secret, period, digits, algorithm, issuer
        case credentialID = "credentialId"
        case rpID = "rpId"
        case userHandle, key
    }

    /// The editable-field mirror (`ASImportableEditableField`): only the
    /// value matters for import; the field type and label are tolerated.
    private struct EditableField: Codable, Sendable {
        let value: String
    }

    /// The pinned CXF encoding FLATTENS each credential's payload into the
    /// same object as the `"type"` discriminator (verified against the real
    /// `ASExportedCredentialData` encoder — e.g.
    /// `{"type":"basic-auth","username":{…},"password":{…}}`).
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(String.self, forKey: .type)
        switch kind {
        case "basic-auth":
            let userName = try container.decodeIfPresent(EditableField.self, forKey: .userName)?.value
            let password = try container.decodeIfPresent(EditableField.self, forKey: .password)?.value
            self = .basicAuthentication(userName: userName, password: password)
        case "totp":
            let secret = try container.decodeIfPresent(Data.self, forKey: .secret) ?? Data()
            let period = try container.decodeIfPresent(Int.self, forKey: .period)
                ?? TOTPGenerator.defaultPeriod
            let digits = try container.decodeIfPresent(Int.self, forKey: .digits)
                ?? TOTPGenerator.defaultDigits
            let userName = try container.decodeIfPresent(String.self, forKey: .userName)
            let algorithm = try container.decodeIfPresent(String.self, forKey: .algorithm) ?? "sha1"
            let issuer = try container.decodeIfPresent(String.self, forKey: .issuer)
            self = .totp(
                secret: secret, period: period, digits: digits,
                userName: userName, algorithm: algorithm, issuer: issuer)
        case "passkey":
            self = .passkey(
                credentialID: try container.decodeIfPresent(Data.self, forKey: .credentialID) ?? Data(),
                rpID: try container.decodeIfPresent(String.self, forKey: .rpID) ?? "",
                userName: try container.decodeIfPresent(String.self, forKey: .userName) ?? "",
                userHandle: try container.decodeIfPresent(Data.self, forKey: .userHandle) ?? Data(),
                key: try container.decodeIfPresent(Data.self, forKey: .key) ?? Data())
        default:
            self = .unsupported(kind: kind)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .basicAuthentication(let userName, let password):
            try container.encode("basic-auth", forKey: .type)
            try container.encodeIfPresent(userName.map(EditableField.init(value:)), forKey: .userName)
            try container.encodeIfPresent(password.map(EditableField.init(value:)), forKey: .password)
        case .totp(let secret, let period, let digits, let userName, let algorithm, let issuer):
            try container.encode("totp", forKey: .type)
            try container.encode(secret, forKey: .secret)
            try container.encode(period, forKey: .period)
            try container.encode(digits, forKey: .digits)
            try container.encodeIfPresent(userName, forKey: .userName)
            try container.encode(algorithm, forKey: .algorithm)
            try container.encodeIfPresent(issuer, forKey: .issuer)
        case .passkey(let credentialID, let rpID, let userName, let userHandle, let key):
            try container.encode("passkey", forKey: .type)
            try container.encode(credentialID, forKey: .credentialID)
            try container.encode(rpID, forKey: .rpID)
            try container.encode(userName, forKey: .userName)
            try container.encode(userHandle, forKey: .userHandle)
            try container.encode(key, forKey: .key)
        case .unsupported(let kind):
            try container.encode(kind, forKey: .type)
        }
    }
}
