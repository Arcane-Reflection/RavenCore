import CryptoKit
import Foundation

/// Errors surfaced by the vendored EFF wordlist.
public enum EffWordlistError: Error, Equatable {
    /// The vendored wordlist resource failed its load-time validation
    /// (04-CONTEXT D-08: exactly 7776 clean lowercase words).
    case wordlistCorrupt
}

/// The vendored EFF large wordlist (04-CONTEXT D-08), validated at load.
///
/// Source: EFF Diceware large wordlist, 7776 words,
/// `https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt`
/// (EFF — Creative Commons CC0 1.0 / public-domain dedication). Vendored
/// 2026-09-13; the dice-number column was stripped so the resource is one
/// lowercase word per LF-terminated line (7776 lines, no comments, no
/// trailing blank). Committed content is pinned byte-for-byte by
/// `GeneratorTests` (SHA-256), mirroring the BIP39 vendor discipline
/// (02-CONTEXT D-08): to update the list, re-run that pin intentionally.
/// The resource file itself must never gain comments — the line-count
/// validation is load-bearing.
public enum EffWordlist {

    private static let validatedWords: [String] = {
        do {
            return try loadAndValidate()
        } catch {
            fatalError("EffWordlist: vendored wordlist failed validation — refusing to generate passphrases on an unvalidated list")
        }
    }()

    /// The EFF large wordlist in file order (index = wordlist position; the
    /// original dice numbering maps 1:1 onto index+1 in base-6 digits).
    public static let words: [String] = validatedWords

    /// Wordlist size — log2(7776) ≈ 12.92 bits of entropy per word.
    public static let wordCount = 7776

    /// Validates the vendored resource against the load-time contract:
    /// exactly 7776 LF-terminated lines, no BOM, no CR, no blank lines,
    /// all lowercase ASCII (plus the few official hyphenated words), no
    /// duplicates. Internal so tests assert resource fidelity directly.
    static func validateResource() throws {
        _ = try loadAndValidate()
    }

    /// Resolves the copied resource — `.copy` preserves the target-relative
    /// directory, so the subdirectory hint is required (Bip39 precedent).
    private static var resourceURL: URL? {
        if let url = Bundle.module.url(
            forResource: "eff-large-wordlist", withExtension: "txt",
            subdirectory: "Generator/Resources") {
            return url
        }
        // Fallback for bundle layouts that flatten copied resources.
        return Bundle.module.url(forResource: "eff-large-wordlist", withExtension: "txt")
    }

    private static func loadAndValidate() throws -> [String] {
        guard let url = resourceURL,
              let data = try? Data(contentsOf: url) else {
            throw EffWordlistError.wordlistCorrupt
        }
        guard !data.starts(with: [0xEF, 0xBB, 0xBF]),
              !data.contains(UInt8(ascii: "\r")),
              data.last == UInt8(ascii: "\n") else {
            throw EffWordlistError.wordlistCorrupt
        }
        let lines = data.split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: true)
        guard lines.count == wordCount else { throw EffWordlistError.wordlistCorrupt }

        var words: [String] = []
        words.reserveCapacity(wordCount)
        var seen = Set<String>(minimumCapacity: wordCount)
        for line in lines {
            guard let word = String(data: Data(line), encoding: .utf8),
                  !word.isEmpty,
                  // Lowercase ASCII letters plus the hyphen (the official
                  // list contains a few hyphenated words, e.g. "drop-down").
                  word.allSatisfy { $0.isASCIILowercaseLetter || $0 == "-" },
                  seen.insert(word).inserted else {
                throw EffWordlistError.wordlistCorrupt
            }
            words.append(word)
        }
        return words
    }
}

extension Character {
    /// ASCII lowercase letter (the vendored charset base).
    fileprivate var isASCIILowercaseLetter: Bool {
        isASCII && ("a"..."z").contains(self)
    }
}
