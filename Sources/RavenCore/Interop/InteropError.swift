import Foundation

/// Errors thrown by the native⇄kdbx interop mapper (05-CONTEXT D-02/D-03).
/// All `Equatable` for exact-case test assertions, mirroring the engine's
/// per-module error enum convention. Payloads never carry vault content —
/// the cases identify the failure shape, nothing else (no values, no paths).
public enum InteropError: Error, Equatable {
    /// A structural name required for the mapping is empty (a kdbx group
    /// with no name cannot become a Folder). Entries with empty titles are
    /// NOT this error — they are skipped and counted honestly in
    /// `ImportSummary.skippedCounts` (counting beats aborting for data).
    case emptyName
    /// An attachment exceeds the engine's per-attachment cap
    /// (`KdbxAttachments.sizeLimitBytes`, 25 MiB). Loud error, never
    /// truncation — same threshold on both kdbx sides (T-05-03).
    case attachmentTooLarge
    /// The document's shape cannot be mapped at state level (e.g. a root
    /// group without a name — nothing from such a file can be placed).
    case unsupportedKdbx
    /// A cross-reference in the input could not be resolved (e.g. an export
    /// folder whose parent id matches no folder in the set).
    case mappingFailed
    /// The CSV bytes are not valid UTF-8, so no text layer exists to parse
    /// (T-05-06: typed failure, never a partial silent parse).
    case csvUnreadable
    /// The CSV carries no records at all — empty bytes, only line breaks, or
    /// a single blank record (nothing to map or preview).
    case emptyFile
}
