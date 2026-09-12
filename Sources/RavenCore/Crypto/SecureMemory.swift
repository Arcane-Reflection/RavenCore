import Foundation
import Security

/// Cryptographically secure random bytes (Security framework).
public enum SecureRandom {
    /// Cryptographically secure random bytes from the system CSPRNG.
    ///
    /// Fail-closed (CWE-703/338 family): a non-zero `SecRandomCopyBytes`
    /// status aborts instead of silently returning deterministic all-zero
    /// material. Every fresh secret in the engine flows through here (data
    /// keys, salts, master/inner seeds, key files) — predictable output would
    /// be a catastrophic fail-open, and an abort is strictly better. The
    /// platform CSPRNG effectively never fails; if it ever does there is no
    /// meaningful recovery, so this is a deliberate library tripwire (same
    /// posture as arc4random/libsodium and the BIP39 wordlist guard
    /// T-02-03): no typed error by design, so no module boundary can be
    /// crossed by an unreachable foreign error case (FW-03's convention).
    public static func bytes(count: Int) -> Data {
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            fatalError("SecureRandom: system CSPRNG failed (status \(status)) — refusing to return predictable key material")
        }
        return data
    }
}

/// Best-effort scrubbing of key material from memory.
public enum SecureMemory {
    /// Overwrites `data` with zeroes. Use on derived keys and recovery secrets
    /// once they are no longer needed in RAM.
    public static func zero(_ data: inout Data) {
        guard !data.isEmpty else { return }
        data.withUnsafeMutableBytes { buffer in
            _ = memset_s(buffer.baseAddress, buffer.count, 0, buffer.count)
        }
    }
}
