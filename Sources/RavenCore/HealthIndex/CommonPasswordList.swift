import Foundation

/// Errors surfaced by the vendored common-password corpus.
public enum CommonPasswordListError: Error, Equatable {
    /// The vendored corpus resource failed its load-time validation
    /// (08-01B plan: exactly 10,000 clean lines, no duplicates).
    case corpusCorrupt
}

/// The vendored common-password corpus (08-CONTEXT D-06/D-07), validated
/// at load — the frequency-sorted weak-password dimension of the v1.1
/// HealthIndex engine foundation.
///
/// Source: SecLists (Daniel Miessler et al.), `Passwords/Common-Credentials/
/// xato-net-10-million-passwords.txt`,
/// `https://github.com/danielmiessler/SecLists` at commit
/// `c205c36a445bff37f8e58a9ec829105cd4975c58` (the latest commit touching
/// that path, 2025-05-08), MIT license. Extraction command (run at the
/// pinned commit):
///
///     head -n 10000 Passwords/Common-Credentials/xato-net-10-million-passwords.txt
///
/// Vendored 2026-09-14, byte-verbatim — the file is sorted most→least
/// common, so the prefix IS the top-10k list. One upstream blank line
/// (line 43) is part of the original data and is kept: validation counts
/// it toward the 10,000 lines but never treats it as a password, so the
/// deduplicated password set holds 9,999 entries. Committed content is
/// pinned byte-for-byte by `CommonPasswordListTests` (SHA-256 + line
/// count), mirroring the BIP39/EFF vendor discipline (02-CONTEXT D-08,
/// 04-CONTEXT D-08): to update the list, re-run that pin intentionally.
/// The resource file itself must never gain comments — the line-count
/// validation is load-bearing.
///
/// This list is the v1.1 *embedded* corpus only. The offline
/// breach-corpus comparison (HIBP-scale) is explicitly v1.2 scope
/// (08-CONTEXT D-06) and, like every health feature, never touches the
/// network (D-07).
enum CommonPasswordList {

    /// Exact LF-line count the vendored resource must have (the
    /// `head -n 10000` extraction contract).
    static let expectedLineCount = 10_000

    private static let validatedPasswords: Set<String> = {
        do {
            return try loadAndValidate()
        } catch {
            fatalError("CommonPasswordList: vendored corpus failed validation — refusing to evaluate password health on an unvalidated list")
        }
    }()

    /// The deduplicated corpus entries (blank lines excluded).
    static let passwords: Set<String> = validatedPasswords

    /// Exact-match corpus membership — the weak-password dimension's only
    /// predicate. Deliberately case-sensitive and unnormalized in the v1.1
    /// foundation: the corpus is consumed exactly as vendored, so the
    /// behavior is fully determined by the pinned resource.
    static func contains(_ password: String) -> Bool {
        validatedPasswords.contains(password)
    }

    /// Validates the vendored resource against the load-time contract:
    /// exactly 10,000 LF-terminated lines, no BOM, no CR, no blank lines
    /// beyond the one documented upstream blank line, no duplicate
    /// non-empty entries. Internal so tests assert resource fidelity and
    /// rejection paths directly.
    static func validateResource() throws {
        _ = try loadAndValidate()
    }

    /// Validates raw corpus bytes and returns the deduplicated password
    /// set — the load-time checks, testable directly with synthetic input
    /// (plan behavior 5).
    static func validate(_ data: Data) throws -> Set<String> {
        guard !data.starts(with: [0xEF, 0xBB, 0xBF]),
              !data.contains(UInt8(ascii: "\r")),
              data.last == UInt8(ascii: "\n") else {
            throw CommonPasswordListError.corpusCorrupt
        }
        let rawLines = data.split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: false)
        // The required trailing LF yields one final empty split piece —
        // drop exactly it so interior blank lines stay countable data.
        let lines = rawLines.dropLast()
        guard lines.count == expectedLineCount else {
            throw CommonPasswordListError.corpusCorrupt
        }

        var passwords = Set<String>(minimumCapacity: expectedLineCount)
        for line in lines {
            guard let entry = String(data: Data(line), encoding: .utf8) else {
                throw CommonPasswordListError.corpusCorrupt
            }
            // The one upstream blank line is data, not a password.
            guard !entry.isEmpty else { continue }
            guard passwords.insert(entry).inserted else {
                throw CommonPasswordListError.corpusCorrupt
            }
        }
        return passwords
    }

    private static func loadAndValidate() throws -> Set<String> {
        guard let url = resourceURL,
              let data = try? Data(contentsOf: url) else {
            throw CommonPasswordListError.corpusCorrupt
        }
        return try validate(data)
    }

    /// Resolves the copied resource — `.copy` preserves the target-relative
    /// directory, so the subdirectory hint is required (EffWordlist
    /// precedent), with a flattened-layout fallback.
    private static var resourceURL: URL? {
        if let url = Bundle.module.url(
            forResource: "common-passwords-top10k", withExtension: "txt",
            subdirectory: "HealthIndex/Resources") {
            return url
        }
        // Fallback for bundle layouts that flatten copied resources.
        return Bundle.module.url(forResource: "common-passwords-top10k", withExtension: "txt")
    }
}
