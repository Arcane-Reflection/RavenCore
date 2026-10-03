import CryptoKit
import Foundation

/// Password/passphrase generation (04-CONTEXT D-07) — a pure, testable
/// module in the open core so the app and (later) the AutoFill extension
/// share one implementation. All randomness comes from `SecureRandom`
/// (SecRandomCopyBytes); every index selection goes through rejection
/// sampling so no modulo bias can thin the effective charset (T-04-04).
public enum PasswordGenerator {

    /// What the generator produces.
    public enum Mode: String, Sendable, Equatable, CaseIterable {
        /// Random characters from the selected charsets.
        case characters
        /// Words from the EFF large wordlist joined by a separator.
        case passphrase
    }

    /// Generator configuration. Bounds are clamped on generate; a
    /// configuration with no usable charset/word source is a typed error,
    /// never a silent fallback.
    public struct Config: Sendable, Equatable {
        public var mode: Mode = .characters

        /// Random mode: total length (clamped to 12...64, roadmap SC3).
        public var length: Int = 20
        public var useLowercase = true
        public var useUppercase = true
        public var useDigits = true
        public var useSymbols = true

        /// Passphrase mode: word count (clamped to 3...10).
        public var wordCount: Int = 6
        /// "." — unambiguous: the EFF list itself contains hyphenated words.
        public var separator: String = "."

        public init() {}

        /// Active charset for random mode, assembled in a fixed order.
        public var charset: String {
            var set = ""
            if useLowercase { set += "abcdefghijklmnopqrstuvwxyz" }
            if useUppercase { set += "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }
            if useDigits { set += "0123456789" }
            if useSymbols { set += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" }
            return set
        }

        /// True when at least one charset group is enabled.
        public var hasCharset: Bool { !charset.isEmpty }

        /// The configuration as it will actually be used (bounds clamped).
        public var clamped: Config {
            var copy = self
            copy.length = min(max(length, 12), 64)
            copy.wordCount = min(max(wordCount, 3), 10)
            return copy
        }
    }

    public enum PasswordGeneratorError: Error, Equatable {
        /// No charset group enabled (random mode) — a configuration state.
        case invalidConfiguration
        /// The vendored wordlist failed validation (load-time tripwire).
        case wordlistCorrupt
    }

    /// Generates a password/passphrase for `config` (bounds clamped).
    public static func generate(config: Config) throws -> String {
        switch config.mode {
        case .characters:
            return try generateCharacters(config: config.clamped)
        case .passphrase:
            return try generatePassphrase(config: config.clamped)
        }
    }

    /// Shannon entropy of `config` in bits (04-CONTEXT D-07: the UI shows
    /// this number and nothing more — honest, verifiable math).
    public static func entropyBits(config: Config) -> Double {
        let clamped = config.clamped
        switch clamped.mode {
        case .characters:
            let count = Double(clamped.charset.count)
            guard count > 1 else { return 0 }
            return log2(count) * Double(clamped.length)
        case .passphrase:
            return log2(Double(EffWordlist.wordCount)) * Double(clamped.wordCount)
        }
    }

    // MARK: - Internals

    private static func generateCharacters(config: Config) throws -> String {
        let charset = Array(config.charset)
        guard let firstOfEach = requiredFirstCharacters(config: config), config.hasCharset else {
            throw PasswordGeneratorError.invalidConfiguration
        }
        var characters = firstOfEach
        while characters.count < config.length {
            characters.append(charset[unbiasedIndex(bound: charset.count)])
        }
        // Shuffle so the guaranteed one-per-group characters are not
        // positionally predictable (Fisher–Yates with unbiased indices).
        for index in (1..<characters.count).reversed() {
            let swap = unbiasedIndex(bound: index + 1)
            characters.swapAt(index, swap)
        }
        return String(characters)
    }

    /// One character per enabled charset group, so a fully-enabled config
    /// always contains every class (04-02-02 acceptance). Empty config → nil.
    private static func requiredFirstCharacters(config: Config) -> [Character]? {
        var result: [Character] = []
        let groups: [(Bool, String)] = [
            (config.useLowercase, "abcdefghijklmnopqrstuvwxyz"),
            (config.useUppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            (config.useDigits, "0123456789"),
            (config.useSymbols, "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
        ]
        for (enabled, group) in groups where enabled {
            let chars = Array(group)
            result.append(chars[unbiasedIndex(bound: chars.count)])
        }
        return result.isEmpty ? nil : result
    }

    private static func generatePassphrase(config: Config) throws -> String {
        let words = EffWordlist.words
        guard words.count == EffWordlist.wordCount else {
            throw PasswordGeneratorError.wordlistCorrupt
        }
        var picked: [String] = []
        picked.reserveCapacity(config.wordCount)
        for _ in 0..<config.wordCount {
            picked.append(words[unbiasedIndex(bound: words.count)])
        }
        return picked.joined(separator: config.separator)
    }

    /// Uniform random index in `0..<bound` via rejection sampling: values in
    /// the top `2^32 % bound` residue band of a 32-bit draw are discarded
    /// instead of wrapped, so no index is overrepresented. 32 bits (not one
    /// byte) are drawn so wordlist-sized bounds (7776) are coverable.
    static func unbiasedIndex(bound: Int) -> Int {
        precondition(bound > 0, "bound must be positive")
        let modulus = UInt32(bound)
        let limit = UInt32.max - (UInt32.max % modulus) // highest fully-coverable value
        while true {
            let bytes = SecureRandom.bytes(count: 4)
            let value = bytes.withUnsafeBytes { $0.load(as: UInt32.self) }
            if value < limit { return Int(value % modulus) }
        }
    }
}
