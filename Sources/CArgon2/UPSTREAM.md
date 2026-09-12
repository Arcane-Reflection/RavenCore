# Vendored: phc-winner-argon2 (Argon2 reference C implementation)

- **Upstream:** https://github.com/P-H-C/phc-winner-argon2
- **Pinned commit:** `f57e61e19229e23c4445b85494dbf7c07de721cb` (2021-06-25, upstream's final commit)
- **License:** CC0 1.0 OR Apache-2.0 (see `LICENSE`) — compatible with this package's MIT.

## Validation record (vendor time, 2026-09-11)

- **RFC 9106 §5.3 Argon2id test vector** (P=32×0x01, S=16×0x02, K=8×0x03,
  X=12×0x04, t=3, m=32, p=4, v=0x13): computed via standalone C driver
  (`argon2_ctx`, Argon2_id) → `0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659`
  — matches RFC 9106 byte-for-byte.
- Swift wrapper (`KeyDerivation.argon2id`) verified byte-identical to direct
  `argon2id_hash_raw` C calls; reference values pinned in
  `Tests/RavenCoreTests/Argon2VendorTests.swift`.

## Update procedure

1. Pick a new upstream commit, review its diff in full (crypto code — audit it).
2. Replace the files below, update the pin line here and in the plan/CONTEXT references.
3. Re-run the KAT suite (`swift test --filter Argon2VendorTests`) — official test
   vectors must pass byte-for-byte before shipping.

## Vendored files

- `include/argon2.h` — public API
- `src/argon2.c`, `src/core.{c,h}`, `src/encoding.{c,h}`, `src/ref.c`, `src/thread.{c,h}`
- `src/blake2/{blake2b.c, blake2.h, blake2-impl.h, blamka-round-ref.h}`

## Deliberately excluded

- `src/opt.c`, `src/blake2/blamka-round-opt.h` — SSE2/`<emmintrin.h>`; breaks arm64
  (iOS device + Apple Silicon simulator). `ref.c` is the portable path and the
  only compression function on arm64 anyway.
- `src/run.c`, `src/bench.c`, `src/test.c`, `kats/` — executable/benchmark/KAT
  material; KAT vectors live in the Swift test suite instead.

## Threads

`src/thread.{c,h}` are vendored and compiled (upstream `core.c` includes
`thread.h` unconditionally at the pinned commit). Lane scheduling affects wall
time only — Argon2 output is deterministic regardless of threading.

## Build integration

SPM C target `CArgon2`: `publicHeadersPath: "include"`, header search paths
`src` and `src/blake2`, explicit `.c` source list. RavenCore depends on the
target. Mirror of the configuration proven by KDBXKit's vendor commit 8fbca47
(see .planning/phases/01-ravencore/01-RESEARCH.md §R-1).
