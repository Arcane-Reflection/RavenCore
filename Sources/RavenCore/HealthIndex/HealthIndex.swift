import CryptoKit
import Foundation

/// Offline password-health indexing (08-CONTEXT D-06/D-07) — a pure,
/// testable module in the open core, the TOTP module precedent applied to
/// the v1.1 health foundation. `evaluate` folds an unlocked vault's record
/// collection into a `HealthReport`: weak-password hits against the
/// embedded SecLists top-10k corpus (`CommonPasswordList`), cross-record
/// reuse groups keyed by SHA-256 of the password, and per-record password
/// age. The report carries record IDs, day counts, and hash keys ONLY —
/// password material never enters the report structure (T-08-04).
///
/// Boundaries locked by 08-CONTEXT:
/// - **v1.1 is engine-only** — no UI, no app-layer call-site; the full
///   leak-corpus health feature (HIBP-scale comparison, health scores,
///   reuse-detection UX) is explicitly v1.2 (D-06). The v1.2 breach
///   corpus stays offline too — local packaging or manual import, never
///   the network (D-07).
/// - Determinism: grouping is keyed by content hash and every list is
///   sorted canonically, so permuted input order yields an equal report.
/// - Clock: `now` is injected (`@Sendable () -> Date` — the repo-wide
///   convention); the age dimension is fully deterministic under it.
///
/// Age honesty note: `DecryptedRecord.createdAt` is the age source — the
/// model has no per-password-change timestamp, so "age" is honestly the
/// record's age, used as a proxy for the password's age. Documented per
/// research A8; a per-password `updatedAt` is a v1.2 model extension.
public enum HealthIndex {

    /// One cross-record password reuse group: the SHA-256 hex of the
    /// shared password (the key — never the password itself) and the
    /// member record IDs, canonically sorted.
    public struct ReuseGroup: Sendable, Equatable {
        /// SHA-256 hex of the shared password — a linking key only.
        ///
        /// - Warning (08 review WR-2): this hash is UNSALTED SHA-256, so it
        ///   is trivially dictionary-reversible for every corpus member of
        ///   `CommonPasswordList` (the top-10k list ships in-bundle — any
        ///   holder of `key` can recover a weak hit by hashing the corpus).
        ///   High-entropy passwords are not practically reversible, but the
        ///   key must still be treated as sensitivity-bearing linkability
        ///   material, never as an anonymous identifier. In-memory linking
        ///   (the v1.1 scope) is the ONLY sanctioned use. If v1.2 persists
        ///   these values (the `HealthReport` persistence plan), it MUST
        ///   switch to HMAC-SHA256 under a per-vault key — a keyed digest
        ///   defeats the corpus dictionary while preserving equality
        ///   linking within the vault — and never store this raw field.
        public let key: String
        /// Records sharing that password, sorted by UUID string.
        public let recordIDs: [UUID]

        /// Creates a group; internal so callers cannot forge hash keys.
        init(key: String, recordIDs: [UUID]) {
            self.key = key
            self.recordIDs = recordIDs
        }
    }

    /// The structural health index of a record collection. Equatable and
    /// `Sendable` by design — the v1.2 feature layers compare and persist
    /// these values. Every field is ID/count/hash/day material; there is
    /// deliberately no password-bearing field anywhere in this structure.
    ///
    /// Persistence caveat (08 review WR-2): persisting a report as-is would
    /// write raw reuse-group `key`s, whose unsalted SHA-256 is corpus-
    /// reversible (see `ReuseGroup.key`). Any v1.2 persistence MUST key the
    /// stored digests with per-vault HMAC-SHA256 instead of the raw field.
    public struct HealthReport: Sendable, Equatable {
        /// Records whose password is in the embedded common-password
        /// corpus, canonically sorted.
        public let weakHitRecordIDs: [UUID]
        /// Reuse groups with two or more members, sorted by group key.
        public let reuseGroups: [ReuseGroup]
        /// Per-record password age in whole days (floored, never
        /// negative), for every participating record.
        public let passwordAgeDays: [UUID: Int]

        /// Creates a report; internal — `HealthIndex.evaluate` is the
        /// single construction path.
        init(
            weakHitRecordIDs: [UUID],
            reuseGroups: [ReuseGroup],
            passwordAgeDays: [UUID: Int]
        ) {
            self.weakHitRecordIDs = weakHitRecordIDs
            self.reuseGroups = reuseGroups
            self.passwordAgeDays = passwordAgeDays
        }
    }

    /// Records participate with a non-empty password on the `.password`
    /// kind — the only payload kind the app's editor attaches a password
    /// to. Evaluate is pure: no IO, no clock read other than `now()`.
    ///
    /// - Parameters:
    ///   - records: the decrypted records to index (typically one vault's
    ///     collection; concatenations group across the boundary).
    ///   - now: injected clock for the age dimension.
    public static func evaluate(
        records: [DecryptedRecord],
        now: @escaping @Sendable () -> Date = { Date() }
    ) -> HealthReport {
        var weakHits: [UUID] = []
        weakHits.reserveCapacity(records.count)
        // Content-hash key → member IDs: identical passwords collide on
        // the hash, and the plaintext never leaves this local scope.
        var reuseBuckets: [String: [UUID]] = [:]
        var ages: [UUID: Int] = [:]
        ages.reserveCapacity(records.count)
        let moment = now()

        for record in records {
            guard record.type == .password, !record.payload.password.isEmpty else { continue }
            let digest = Data(SHA256.hash(data: Data(record.payload.password.utf8)))
                .map { String(format: "%02x", $0) }.joined()
            reuseBuckets[digest, default: []].append(record.id)
            if CommonPasswordList.contains(record.payload.password) {
                weakHits.append(record.id)
            }
            ages[record.id] = ageDays(from: record.createdAt, to: moment)
        }

        // Canonical ordering: permutation-stable equality (plan behavior 7).
        let sortedWeakHits = weakHits.sorted { $0.uuidString < $1.uuidString }
        let groups = reuseBuckets
            .filter { $0.value.count >= 2 }
            .map { ReuseGroup(key: $0.key, recordIDs: $0.value.sorted { $0.uuidString < $1.uuidString }) }
            .sorted { $0.key < $1.key }

        return HealthReport(
            weakHitRecordIDs: sortedWeakHits,
            reuseGroups: groups,
            passwordAgeDays: ages)
    }

    /// Whole days between `from` and `to`, floored; a same-day or future
    /// timestamp honestly reports 0 — the proxy clock never lies forward.
    private static func ageDays(from createdAt: Date, to now: Date) -> Int {
        max(0, Int(now.timeIntervalSince(createdAt) / 86_400))
    }
}
