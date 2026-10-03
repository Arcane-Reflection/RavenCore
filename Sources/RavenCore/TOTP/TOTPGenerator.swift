import CryptoKit
import Foundation

/// RFC 6238 TOTP code generation (06-CONTEXT D-06) — a pure, testable
/// module in the open core so the app and the AutoFill extension share one
/// implementation (the Phase 4 D-07 `PasswordGenerator` placement logic).
/// HMACs come from CryptoKit; `HMAC<Insecure.SHA1>` covers the
/// legacy-required SHA-1 column — the `Insecure.` spelling is the
/// deliberate signal that the algorithm exists here only because TOTP
/// registrations demand it. Dynamic truncation follows RFC 4226 §5.3
/// exactly — the RFC 6238 Appendix B vectors are the correctness oracle
/// (no "improvements"), pinned by `TOTPGeneratorTests`.
public enum TOTPGenerator {

    /// The hash behind the HMAC step — raw values are the otpauth
    /// `algorithm` spellings.
    public enum Algorithm: String, Sendable, Equatable, CaseIterable {
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha512 = "SHA512"
    }

    /// Typed failures — plain cases only, so error payloads never carry
    /// secret material (repo-wide `Error, Equatable` discipline).
    public enum TOTPError: Error, Equatable {
        /// Only 6- and 8-digit codes exist in the wild and the otpauth standard.
        case invalidDigits
        /// The step must be a positive number of seconds.
        case invalidPeriod
    }

    /// RFC 6238 §4.1/§5.1–5.2 defaults. These also back bare secrets, per
    /// the 06-02 D-07 storage decision (verbatim storage, parameters parsed
    /// at generation time).
    public static let defaultPeriod = 30
    public static let defaultDigits = 6

    /// The code for `secret` at the instant `now` returns (injected-clock
    /// convention — the UI, the extension, and the tests drive the same
    /// clock). Counter: 8-byte big-endian floor(unixTime / period);
    /// truncation: RFC 4226 §5.3; output: zero-padded mod 10^digits.
    public static func code(
        secret: [UInt8],
        algorithm: Algorithm = .sha1,
        digits: Int = defaultDigits,
        period: Int = defaultPeriod,
        at now: @escaping @Sendable () -> Date = { Date() }
    ) throws -> String {
        guard digits == 6 || digits == 8 else { throw TOTPError.invalidDigits }
        guard period > 0 else { throw TOTPError.invalidPeriod }
        let time = now().timeIntervalSince1970
        let counter = time > 0 ? UInt64(time) / UInt64(period) : 0
        return truncatedCode(secret: secret, algorithm: algorithm, digits: digits, counter: counter)
    }

    /// Seconds left in the period at `moment` (1...period) — drives the
    /// E17 detail countdown bar and the E24 extension rows from the SAME
    /// period math the code computation uses.
    public static func secondsRemaining(period: Int, at moment: Date) -> Int {
        guard period > 0 else { return 0 }
        let elapsed = Int(moment.timeIntervalSince1970) % period
        return period - elapsed
    }

    // MARK: - Internals

    /// RFC 4226 §5.3 over an explicit counter — the pure core the
    /// time-based entry delegates to.
    private static func truncatedCode(
        secret: [UInt8],
        algorithm: Algorithm,
        digits: Int,
        counter: UInt64
    ) -> String {
        let counterData = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: Data(secret))
        let mac: [UInt8]
        switch algorithm {
        case .sha1:
            mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))
        case .sha256:
            mac = Array(HMAC<SHA256>.authenticationCode(for: counterData, using: key))
        case .sha512:
            mac = Array(HMAC<SHA512>.authenticationCode(for: counterData, using: key))
        }
        // Dynamic truncation: the low 4 bits of the last byte select the
        // offset; read 31 bits big-endian from there.
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let binary = (Int(mac[offset]) & 0x7F) << 24
            | (Int(mac[offset + 1]) & 0xFF) << 16
            | (Int(mac[offset + 2]) & 0xFF) << 8
            | (Int(mac[offset + 3]) & 0xFF)
        var modulus = 1
        for _ in 0..<digits { modulus *= 10 }
        // Left-pad to exactly `digits` — `padding(toLength:)` pads on the
        // RIGHT, which would corrupt the code (caught by the 07081804 vector).
        var code = String(binary % modulus)
        while code.count < digits {
            code = "0" + code
        }
        return code
    }
}
