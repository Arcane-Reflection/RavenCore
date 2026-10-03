import Foundation

/// The code-generation parameter set `{secret, issuer, algorithm, digits,
/// period}` (06-CONTEXT D-07). `algorithm`/`digits`/`period` always carry
/// concrete values (RFC defaults when the URI omitted them) so generation
/// paths never re-default.
public struct OTPAuthParameters: Sendable, Equatable {
    /// The Base32 secret, verbatim from the source value.
    public let secret: String
    /// The issuer: the `issuer` parameter, else the "Issuer:account"
    /// label prefix, else nil.
    public let issuer: String?
    public let algorithm: TOTPGenerator.Algorithm
    public let digits: Int
    public let period: Int
    /// HOTP counter (RFC 4226) — present only on hotp URIs carrying
    /// one. Counter-based codes are out of scope (D-07).
    public let counter: Int?

    /// `false` only for counter-based HOTP — never live-generate those.
    public var isGeneratable: Bool { counter == nil }

    public init(
        secret: String,
        issuer: String?,
        algorithm: TOTPGenerator.Algorithm,
        digits: Int,
        period: Int,
        counter: Int? = nil
    ) {
        self.secret = secret
        self.issuer = issuer
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.counter = counter
    }
}

/// The single otpauth:// parser (06-CONTEXT D-07): one engine function
/// serves CSV import, kdbx import, code generation, and the E18 edit-field
/// gate — hoisted from `VaultCSVMapper.otpauthSecret`, which is now a thin
/// wrapper over `secret(in:)`.
///
/// Two contracts, one parser:
/// - `parse(_:)` — the FULL generation parameter set
///   `{secret, issuer, algorithm, digits, period}` for code paths. STRICT
///   (RESEARCH V5 / T-06-11): a missing secret, an unknown URI type, or a
///   present-but-malformed parameter value returns nil — never a silent
///   default that would generate silently-wrong codes (RESEARCH Pitfall 8).
/// - `secret(in:)` — the import-extraction semantics the CSV/kdbx mappers
///   always had: an otpauth URI yields its secret parameter, any other
///   non-blank value is a bare secret. Import keeps data; generation gates
///   on the strict parse.
///
/// Grammar per the Google Authenticator Key-URI fact standard (D-07
/// reference): `otpauth://totp/Issuer:account?secret=…&issuer=…&algorithm=
/// SHA1|SHA256|SHA512&digits=6|8&period=30` — absent parameters default to
/// RFC 6238 values (SHA-1 / 6 / 30). HOTP URIs parse with `counter`
/// recorded (out of scope for live generation — `isGeneratable` false only
/// when a counter is present); a counter-less hotp URI keeps period
/// semantics.
public enum OTPAuthURIParser {

    /// The strict generation parse. Bare (non-URI) values pass through with
    /// RFC defaults; otpauth URIs must fully validate or the result is nil.
    public static func parse(_ value: String) -> OTPAuthParameters? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("otpauth://") else {
            guard !trimmed.isEmpty else { return nil }
            return OTPAuthParameters(
                secret: trimmed, issuer: nil,
                algorithm: .sha1, digits: TOTPGenerator.defaultDigits,
                period: TOTPGenerator.defaultPeriod)
        }
        guard let components = URLComponents(string: trimmed),
              let queryItems = components.queryItems,
              let secret = queryItems.first(where: { $0.name.lowercased() == "secret" })?.value,
              !secret.isEmpty else {
            return nil // missing secret ⇒ fail-closed (V5)
        }
        // Type: totp or hotp only — anything else (or nothing) is not a
        // code-generating URI.
        let type = components.host?.lowercased()
        guard type == "totp" || type == "hotp" else { return nil }

        guard let algorithm = parsedAlgorithm(in: queryItems),
              let digits = parsedDigits(in: queryItems),
              let period = parsedPeriod(in: queryItems) else {
            return nil
        }
        // HOTP counter: recorded only when present (hotp host). A malformed
        // counter fails closed like every other parameter.
        var counter: Int?
        if type == "hotp", let raw = queryValue("counter", in: queryItems) {
            guard let parsed = Int(raw), parsed >= 0 else { return nil }
            counter = parsed
        }
        return OTPAuthParameters(
            secret: secret,
            issuer: parsedIssuer(in: queryItems) ?? issuerFromLabel(components.path),
            algorithm: algorithm,
            digits: digits,
            period: period,
            counter: counter)
    }

    /// The import-extraction contract (verbatim hoist of the pre-06-02
    /// `VaultCSVMapper.otpauthSecret`): an otpauth URI yields its secret
    /// query parameter — no other validation, so imports keep every value
    /// they have always kept; any other non-blank value is a bare secret.
    public static func secret(in value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("otpauth://") else {
            return trimmed.isEmpty ? nil : trimmed
        }
        guard let components = URLComponents(string: trimmed),
              let queryItems = components.queryItems,
              let secret = queryItems.first(where: { $0.name.lowercased() == "secret" })?.value,
              !secret.isEmpty else {
            return nil
        }
        return secret
    }

    // MARK: - Parameter helpers (all case-insensitive on names)

    private static func queryValue(_ name: String, in items: [URLQueryItem]) -> String? {
        items.first(where: { $0.name.lowercased() == name })?.value
    }

    private static func parsedAlgorithm(in items: [URLQueryItem]) -> TOTPGenerator.Algorithm? {
        guard let raw = queryValue("algorithm", in: items) else {
            return .sha1 // RFC default
        }
        return TOTPGenerator.Algorithm(rawValue: raw.uppercased())
    }

    private static func parsedDigits(in items: [URLQueryItem]) -> Int? {
        guard let raw = queryValue("digits", in: items) else {
            return TOTPGenerator.defaultDigits // RFC default
        }
        guard let digits = Int(raw), digits == 6 || digits == 8 else { return nil }
        return digits
    }

    private static func parsedPeriod(in items: [URLQueryItem]) -> Int? {
        guard let raw = queryValue("period", in: items) else {
            return TOTPGenerator.defaultPeriod // RFC default
        }
        guard let period = Int(raw), period > 0 else { return nil }
        return period
    }

    /// Issuer parameter (non-empty wins over the label prefix).
    private static func parsedIssuer(in items: [URLQueryItem]) -> String? {
        guard let issuer = queryValue("issuer", in: items), !issuer.isEmpty else { return nil }
        return issuer
    }

    /// The "Issuer:account" label prefix (percent-decoded), nil when absent.
    private static func issuerFromLabel(_ path: String) -> String? {
        let label = path.hasPrefix("/") ? String(path.dropFirst()) : path
        guard let colon = label.firstIndex(of: ":") else { return nil }
        let prefix = String(label[label.startIndex..<colon])
        let decoded = prefix.removingPercentEncoding ?? prefix
        return decoded.isEmpty ? nil : decoded
    }
}
