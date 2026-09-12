# RavenCore

[![CI](https://github.com/Arcane-Reflection/RavenCore/actions/workflows/ci.yml/badge.svg)](https://github.com/Arcane-Reflection/RavenCore/actions/workflows/ci.yml)

MIT-licensed open-source engine of **RavenVault** — an offline-first,
one-time-purchase iOS password vault and seed-phrase cold storage. RavenVault is
open core: the engine (formats, cryptography, recovery math) lives here under MIT
and accepts community review; the app layer is proprietary.

Zero third-party dependencies. Zero network. Swift 6 strict concurrency throughout.

## Capabilities & formats

Every row is traceable to the module that implements it.

| Capability | Details | Source |
|---|---|---|
| KDBX 4.0 / 4.1 read + write | Outer header, HMAC block stream, inner header, XML document model; round-trip fidelity (history, custom fields, unknown fields, recycle bin) verified against a KeePassXC-generated corpus | `Sources/RavenCore/Keepass/KdbxReader.swift`, `KdbxWriter.swift` |
| KDBX 3.1 read-only | Reads into the same unified document model; writing a 3.1-derived document always produces 4.x | `Sources/RavenCore/Keepass/KdbxReader.swift` |
| Attachments (binary pool) | Binary inner-header pool read/write, attachment records | `Sources/RavenCore/Keepass/KdbxInnerHeader.swift`, `BinaryIO.swift` |
| Composite keys & key files | `.key` (XML v1.0), `.keyx` (XML v2.0), 32-byte raw, 64-hex — alone or combined with a password | `Sources/RavenCore/Keepass/KdbxCompositeKey.swift`, `KeyFile.swift` |
| KDF: Argon2id (default m=64 MiB, t=3, p=2), Argon2d, AES-KDF | KDF and parameters persist per-database in the KDBX header; vendored reference C implementation | `Sources/RavenCore/Crypto/KeyDerivation.swift`, `Sources/CArgon2/` (see `Sources/CArgon2/UPSTREAM.md`) |
| Outer encryption: AES-256-CBC, ChaCha20 | Cipher UUID negotiated from the database header | `Sources/RavenCore/Keepass/KdbxCrypto.swift` |
| Passkey attributes (KeePassXC 2.7.x compatible) | `KPEX_PASSKEY_*` seven-attribute read/write with exact protection flags; backup eligible/state flags default to `true` when absent; reads tolerate legacy key spellings | `Sources/RavenCore/Keepass/Passkey.swift` |
| Shamir secret sharing, 3-of-5 | GF(2⁸), polynomial 0x11D (the ssss / HashiCorp Vault scheme) | `Sources/RavenCore/Shamir/ShamirSecretSharing.swift` |
| Shamir paper format v1 | Printable, checksummed (CRC-32) share encoding; corruption is rejected before any reconstruction. Spec: [Docs/SHAMIR-PAPER-FORMAT.md](Docs/SHAMIR-PAPER-FORMAT.md) · vectors: [Docs/TEST-VECTORS/shamir-paper-v1.json](Docs/TEST-VECTORS/shamir-paper-v1.json) | `Sources/RavenCore/Shamir/ShamirPaperFormat.swift` |
| BIP39 (English) | 12/24-word validation, checksum verification, entropy ⇄ mnemonic, 512-bit seed derivation (PBKDF2-HMAC-SHA512, NFKD-normalized passphrase). Wordlist vendored byte-verbatim from bitcoin/bips, pinned `ce1862ac6bcffa1dd20aad858380e51e66e949ea` (MIT) | `Sources/RavenCore/Seed/Bip39.swift`, `Sources/RavenCore/Seed/Resources/bip39-english.txt` |
| SeedQR Standard / Compact | Standard = 4-digit word indices; Compact = raw entropy bytes (16/32). Full BIP39 checksum gate on decode. Vectors: [Docs/TEST-VECTORS/seedqr-vectors.json](Docs/TEST-VECTORS/seedqr-vectors.json) | `Sources/RavenCore/Seed/SeedQR.swift` |
| Vault model + append-only log | Chain-hashed, tamper-evident record history; archive/compact; dual key-wrap design | `Sources/RavenCore/Vault/VaultService.swift`, `AppendOnlyLog.swift`, `VaultModels.swift` |

QR imaging (matrix generation/scanning) and recovery ceremony UX are **not** part
of this package — they live in the app layer.

## Quick start

macOS with Xcode 16+ (the package manifest is `swift-tools-version: 6.0`):

```bash
cd Packages/RavenCore
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

The suite includes the KDBX corpus gate: every committed KeePassXC-generated
fixture (`Tests/Fixtures/Kdbx/`) must read and must reject wrong credentials,
and each must round-trip through a semantic write→read pass — with one
documented exception: `kxc-attachment.kdbx` is read-only (its binaries live in
the 3.1 meta section, so the writer's dangling-ref validation correctly refuses
its 4.0 upgrade, and the gate pins that loud failure). Every RavenCore-written
fixture is verified attribute-by-attribute with `keepassxc-cli 2.7.12` (evidence recorded in the RavenVault development repository). Published format vectors in
`Docs/TEST-VECTORS/` are the single source of truth — the tests read the same
JSON files, so tests and the public contract cannot drift.

## Security model

- **Argon2id defaults m=64 MiB / t=3 / p=2** (`Crypto/KeyDerivation.swift`);
  KDF and parameters are stored per database, and legacy KDFs stay permanently
  readable (format-versioned, never a lock-in).
- **Zero third-party dependencies** — system frameworks only (Foundation,
  CryptoKit, CommonCrypto, Security) plus the vendored Argon2 reference C.
- **Zero network** — no network symbols anywhere in the engine or app; the
  repo-wide grep gate in this repository's CI and RavenVault's development pipeline
  fails the build on any hit.
- **Vendored Argon2 provenance** — upstream pin, license, validation record and
  update procedure: `Sources/CArgon2/UPSTREAM.md`.
- **Interoperability is gated, not claimed** — the KeePassXC corpus gate (this
  repo, `Tests/Fixtures/Kdbx/`) carries the evidence; oracle transcripts live in
  the RavenVault development repository.
- Secret material is scrubbed where lifetimes allow (`Crypto/SecureMemory.swift`);
  credential errors are typed enums that never echo secret values.

## License

- This package: MIT — see [`LICENSE`](LICENSE).
- Embedded BIP39 English wordlist: MIT, from bitcoin/bips (pinned
  `ce1862ac6bcffa1dd20aad858380e51e66e949ea`), vendored byte-verbatim.
- Vendored Argon2: CC0 1.0 OR Apache-2.0 (upstream phc-winner-argon2) —
  see `Sources/CArgon2/UPSTREAM.md`.
- The RavenVault app layer is proprietary until the project's public
  maintenance commitment fires; terms: `Docs/AGPL-COMMITMENT.md`.
