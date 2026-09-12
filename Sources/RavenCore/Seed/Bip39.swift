import CryptoKit
import Foundation

/// Errors thrown by BIP39 validation and conversion. All `Equatable` for
/// exact-case test assertions; no case carries a word value or entropy value
/// (mnemonic material never leaks through error payloads).
public enum Bip39Error: Error, Equatable {
    /// Entropy is not 16 or 32 bytes (only 12/24-word phrases are exposed, D-07).
    case invalidEntropyLength
    /// Mnemonic is not 12 or 24 words.
    case invalidWordCount
    /// A word is not in the English wordlist.
    case unknownWord
    /// The recomputed checksum does not match the phrase's trailing bits —
    /// the phrase is not a valid BIP39 mnemonic and must never be accepted
    /// for cold storage (T-02-01).
    case invalidChecksum
    /// The vendored wordlist resource failed its load-time validation
    /// (T-02-03 tripwire: checksum judgments must never run on a corrupt list).
    case wordlistCorrupt
}

/// The vendored BIP39 English wordlist (D-08), validated at load.
///
/// Provenance (mirrors `Sources/CArgon2/UPSTREAM.md`):
///
/// 1. **Upstream:** https://raw.githubusercontent.com/bitcoin/bips/bip-0039/english.txt
///    (repository github.com/bitcoin/bips, path `bip-0039/english.txt`)
/// 2. **Pinned commit:** `ce1862ac6bcffa1dd20aad858380e51e66e949ea`
///    (2014-02-07 — the file has a single-commit history and is unchanged since)
/// 3. **License:** MIT (bitcoin/bips)
/// 4. **Validation record:** vendored byte-verbatim on 2026-09-12; SHA-256
///    `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
///    (the canonical value pinned by trezor/python-mnemonic's own test suite);
///    2048 LF lines, no BOM, strictly sorted, all `[a-z]`, first `abandon`,
///    last `zoo`. Re-asserted on every load by `validateResource()` and in
///    `Bip39Tests` (word-index fidelity is anchored by the TREZOR vectors).
/// 5. **Update procedure:** never edit in place. Re-vendor byte-verbatim from
///    a new bitcoin/bips commit, update this pin, and re-run the wordlist
///    fidelity tests. `Package.swift` declares the resource with `.copy`
///    precisely so builds cannot rewrite the bytes.
///
/// The file lives at `Seed/Resources/bip39-english.txt` and ships as an SPM
/// resource; lookup is bundle-relative with no runtime network access (T-02-04).
public enum Bip39Wordlist {

    /// A wordlist that failed validation is a vendored-resource tripwire
    /// (T-02-03): every checksum pass/fail judgment would be wrong, so the
    /// process refuses to run BIP39 logic at all rather than guess. This can
    /// only fire if the committed resource was tampered with or the SPM
    /// resource bundle is broken — `Bip39Tests` pins the committed bytes.
    /// Release-doc note (02-REVIEW.md I-04, documented-deliberate): a broken
    /// SPM resource bundle surfaces as this crash at first BIP39 use, never
    /// as a wrong checksum verdict — fail closed beats fail wrong.
    private static let validatedWords: [String] = {
        do {
            return try loadAndValidateEnglish()
        } catch {
            fatalError("Bip39Wordlist: vendored wordlist failed validation — refusing to run checksum logic on an unvalidated list (T-02-03)")
        }
    }()

    /// The English wordlist in BIP39 index order (index = wordlist position).
    public static let english: [String] = validatedWords

    /// 0-based word → index table, built once from `english`.
    public static let englishIndices: [String: Int] = {
        var table: [String: Int] = .init(minimumCapacity: english.count)
        for (index, word) in english.enumerated() {
            table[word] = index
        }
        return table
    }()

    /// Validates the vendored resource against the load-time contract:
    /// exactly 2048 LF-terminated lines, no BOM, no CR, all `[a-z]`,
    /// strictly sorted. Internal so tests assert resource fidelity directly.
    static func validateResource() throws {
        _ = try loadAndValidateEnglish()
    }

    private static func loadAndValidateEnglish() throws -> [String] {
        guard let url = resourceURL,
              let data = try? Data(contentsOf: url) else {
            throw Bip39Error.wordlistCorrupt
        }
        // UTF-8 BOM, CRLF line endings, or a missing final newline would all
        // shift line boundaries or violate the byte-verbatim vendor contract.
        guard !data.starts(with: [0xEF, 0xBB, 0xBF]),
              !data.contains(UInt8(ascii: "\r")),
              data.last == UInt8(ascii: "\n") else {
            throw Bip39Error.wordlistCorrupt
        }
        let lines = data.split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: true)
        guard lines.count == 2048 else { throw Bip39Error.wordlistCorrupt }

        var words: [String] = []
        words.reserveCapacity(2048)
        var previous = ""
        for line in lines {
            // Strict `[a-z]` byte check: non-empty, no whitespace, no UTF-8
            // multibyte sequences can pass.
            guard !line.isEmpty,
                  line.allSatisfy({ $0 >= 0x61 && $0 <= 0x7A }) else {
                throw Bip39Error.wordlistCorrupt
            }
            let word = String(decoding: line, as: UTF8.self)
            guard previous.isEmpty || word > previous else {
                throw Bip39Error.wordlistCorrupt
            }
            words.append(word)
            previous = word
        }
        return words
    }

    /// SPM's `.copy` rule preserves the bundle-relative path; some build
    /// systems flatten resources to the bundle root instead, so both layouts
    /// are tried before declaring the bundle broken.
    private static var resourceURL: URL? {
        if let url = Bundle.module.url(
            forResource: "bip39-english", withExtension: "txt",
            subdirectory: "Seed/Resources") {
            return url
        }
        return Bundle.module.url(forResource: "bip39-english", withExtension: "txt")
    }
}

/// BIP39 mnemonic generation, validation, and mnemonic→seed derivation
/// (CORE-09). English wordlist only (D-08); only 12- and 24-word phrases are
/// exposed (D-07) though the checksum math below is the general BIP39 scheme.
///
/// Spec (bip-0039.mediawiki): for ENT bits of entropy, CS = ENT/32 checksum
/// bits are taken from the leading bits of `SHA-256(entropy)`. The ENT‖CS bit
/// stream is split MSB-first into 11-bit groups; each group indexes the sorted
/// 2048-word list. 12 words ⇔ ENT=128/CS=4; 24 words ⇔ ENT=256/CS=8.
///
/// `seed(mnemonic:passphrase:)` is PBKDF2-HMAC-SHA512 (2048 iterations,
/// 64-byte output) over password = NFKD(mnemonic) and salt =
/// `"mnemonic" + NFKD(passphrase)`. NFKD uses Foundation's
/// `decomposedStringWithCompatibilityMapping`; the wordlist is pure ASCII so
/// normalization is the identity on mnemonics, but it is applied anyway for a
/// single uniform code path — and it is load-bearing on the passphrase, where
/// skipping it would silently fork from every reference wallet.
///
/// Memory hygiene (T-02-02): scratch bit buffers are zeroed before release
/// (`SecureMemory.zero` semantics) where the lifetime allows it. The returned
/// seed/entropy `Data` is the caller's secret material and cannot be scrubbed
/// here; the `[String]` mnemonic is Swift-managed memory and not scrubbable —
/// the same documented `String` limitation as CONCERNS.md.
public enum Bip39 {

    /// Generates a mnemonic from 16 or 32 bytes of entropy (12 or 24 words).
    public static func mnemonic(fromEntropy entropy: Data) throws -> [String] {
        guard entropy.count == 16 || entropy.count == 32 else {
            throw Bip39Error.invalidEntropyLength
        }
        let checksumBitCount = entropy.count * 8 / 32   // 4 for 128-bit, 8 for 256-bit
        let expectedWordCount = entropy.count == 16 ? 12 : 24

        // CS = first checksumBitCount bits of SHA-256(entropy); both sizes fit
        // in the digest's first byte.
        let checksumByte = Array(SHA256.hash(data: entropy))[0]

        var words: [String] = []
        words.reserveCapacity(expectedWordCount)
        var accumulator = 0
        var accumulatorBits = 0

        func feed(_ byte: UInt8) {
            accumulator = (accumulator << 8) | Int(byte)
            accumulatorBits += 8
            while accumulatorBits >= 11 {
                accumulatorBits -= 11
                let index = (accumulator >> accumulatorBits) & 0x7FF
                words.append(Bip39Wordlist.english[index])
            }
        }

        for byte in entropy {
            feed(byte)
        }
        feed(checksumByte)

        // ENT + CS is an exact multiple of 11 for both sizes, so the stream
        // terminates on a word boundary.
        assert(words.count == expectedWordCount)
        return words
    }

    /// Validates `words` and returns the entropy it encodes.
    public static func entropy(fromMnemonic words: [String]) throws -> Data {
        try validate(words)
        return try entropyBytes(fromValidatedWords: words)
    }

    /// Validates a mnemonic: word count ∈ {12, 24}, every word in the
    /// wordlist, and a matching BIP39 checksum. Any failure is a typed error
    /// (T-02-01: an invalid phrase must never be accepted into cold storage).
    public static func validate(_ words: [String]) throws {
        guard words.count == 12 || words.count == 24 else {
            throw Bip39Error.invalidWordCount
        }
        for word in words {
            guard Bip39Wordlist.englishIndices[word] != nil else {
                throw Bip39Error.unknownWord
            }
        }
        _ = try entropyBytes(fromValidatedWords: words)
    }

    /// Derives the 64-byte BIP39 seed (PBKDF2-HMAC-SHA512, 2048 iterations,
    /// salt `"mnemonic" + NFKD(passphrase)`). The mnemonic is validated first.
    public static func seed(mnemonic words: [String], passphrase: String) throws -> Data {
        try validate(words)
        let normalizedMnemonic = words.joined(separator: " ")
            .decomposedStringWithCompatibilityMapping
        let normalizedSalt = "mnemonic" + passphrase.decomposedStringWithCompatibilityMapping
        return try KeyDerivation.pbkdf2SHA512(
            password: Data(normalizedMnemonic.utf8),
            salt: Data(normalizedSalt.utf8),
            iterations: 2048,
            outputLength: 64
        )
    }

    // MARK: - Internals

    /// Reassembles ENT from the 11-bit index stream and verifies CS.
    /// Caller has already validated count and wordlist membership.
    private static func entropyBytes(fromValidatedWords words: [String]) throws -> Data {
        let entropyBitCount = words.count == 12 ? 128 : 256
        let checksumBitCount = words.count == 12 ? 4 : 8
        let entropyByteCount = entropyBitCount / 8

        var bits: [UInt8] = []
        bits.reserveCapacity(entropyByteCount + 1)
        var accumulator = 0
        var accumulatorBits = 0
        for word in words {
            accumulator = (accumulator << 11) | Bip39Wordlist.englishIndices[word]!
            accumulatorBits += 11
            while accumulatorBits >= 8 {
                accumulatorBits -= 8
                bits.append(UInt8((accumulator >> accumulatorBits) & 0xFF))
            }
        }

        // ENT‖CS is only byte-aligned for 24-word phrases (264 bits = 33
        // bytes); for 12-word phrases it is 132 bits = 16 full ENT bytes with
        // the 4 checksum bits still sitting in the accumulator. Read the
        // received checksum from whichever position holds it.
        let expectedByteCount = (entropyBitCount + checksumBitCount) / 8
        guard bits.count == expectedByteCount else {
            throw Bip39Error.invalidChecksum
        }
        let entropy = Data(bits.prefix(entropyByteCount))
        let expectedChecksum = Int(Array(SHA256.hash(data: entropy))[0]) >> (8 - checksumBitCount)
        let receivedChecksum: Int
        if accumulatorBits > 0 {
            receivedChecksum = accumulator & ((1 << accumulatorBits) - 1)
        } else {
            receivedChecksum = Int(bits[bits.count - 1]) & ((1 << checksumBitCount) - 1)
        }

        // Scrub the scratch copy of ENT‖CS (T-02-02); the returned Data is the
        // caller's material by design.
        bits.withUnsafeMutableBufferPointer { buffer in
            _ = memset_s(buffer.baseAddress, buffer.count, 0, buffer.count)
        }

        guard receivedChecksum == expectedChecksum else {
            throw Bip39Error.invalidChecksum
        }
        return entropy
    }
}
