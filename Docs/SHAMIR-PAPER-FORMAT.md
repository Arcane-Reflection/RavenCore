# RavenVault Shamir Share Paper Format — v1

**Format name:** `ravenvault-shamir-paper` · **Version:** 1
**Text encoding:** `crockford-base32` · **Checksum:** `crc-32/iso-hdlc`

This document specifies the printable, self-describing encoding of a single
Shamir secret share, suitable for transcription onto paper and for
QR-alphanumeric rendering. It is a pure encoding layer: shares themselves are
produced by Shamir's Secret Sharing over GF(2^8) with primitive polynomial
0x11D (the classic `ssss` scheme); this document says nothing about how
shares are generated or combined, only how one share is written on paper.

**Status:** this is a published contract. Once implementers have transcribed
shares to paper, the meaning of existing encodings can never change. Future
versions are introduced **additively** through a new version byte (see
[Versioning](#versioning)); v1 encoding semantics are frozen forever.

## 1. Byte layout (per share)

A share is serialized to a byte string before text encoding:

| Offset   | Size   | Field        | Meaning                                              |
| -------- | ------ | ------------ | ---------------------------------------------------- |
| 0        | 1      | `version`    | `0x01` for this specification                        |
| 1        | 1      | `threshold`  | minimum shares `k` required to reconstruct (2…255)   |
| 2        | 1      | `total`      | number of shares `n` that were created (k ≤ n ≤ 255) |
| 3        | 1      | `index`      | this share's index `x`, 1…255                        |
| 4        | 1      | `value_len`  | share value length `L` in bytes (1…255)              |
| 5…4+L    | L      | `value`      | the share value (the polynomial evaluations)         |
| 5+L…8+L  | 4      | `checksum`   | CRC-32 over bytes `0…4+L`, big-endian                |

Total encoded byte count: `B = 9 + L`.

The header makes every paper share **self-describing**: "any 3 of 5" is
printed on the paper itself, so a recovery ceremony needs no side channel to
know how many shares to collect or how to number them.

## 2. Text encoding: crockford-base32

The byte string is encoded in Crockford Base32 (crockford.com/base32.html,
2019) with the following exact rules — stated verbatim because base32
variants are the number-one source of interop failure in ad-hoc codecs:

### 2.1 Encode alphabet

```
Value:   0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
Symbol:  0 1 2 3 4 5 6 7 8 9  A  B  C  D  E  F  G  H  J  K  M  N  P  Q  R  S  T  V  W  X  Y  Z
```

The letters `I`, `L`, `O` and `U` are never emitted. Encoding output is
uppercase only.

### 2.2 Bit mapping and fixed width

The byte string is mapped MSB-first into a bit stream, sliced into 5-bit
groups; each group indexes the alphabet above. The final group is
zero-padded on the right (low bits) to reach 5 bits.

The result is then **left-padded with the symbol `0` to the fixed width**:

```
width = ceil(8·B/5),  where B = 9 + L
```

so every share of a given secret prints at an identical width and leading
zero bytes are unambiguous. Example: a 32-byte share value gives
`B = 9 + 32 = 41` encoded bytes and `ceil(8·B/5) = ceil(328/5) = 66`
characters.

### 2.3 Decode normalization

Decoding is case-insensitive and applies the Crockford human-transcription
aliases:

- `I` / `i` and `L` / `l` are read as `1`
- `O` / `o` is read as `0`
- The hyphen `-` (group separator, §3) is ignored
- **`U` / `u` is rejected** — it is reserved for Crockford's mod-37-2^5
  checksum symbol, which this format deliberately does not use (integrity
  comes from the CRC-32, §4). Accepting `U` would mask a whole class of
  transcription errors where another symbol was misread.
- Any other symbol outside the alphabet is rejected.
- **Canonical padding:** the final character's unused low bits must be zero
  (exactly what §2.2 emits). A string whose padding bits are set is not the
  canonical encoding of any byte string and must be rejected as
  mis-transcribed.

## 3. Presentation (printing)

- The fixed-width character string is split into groups of 5 characters,
  separated by `-`. The final group may be shorter. Example shape:
  `3R4V3-N1GHT-…-X` (66 characters → 13 groups of 5 + 1 group of 1).
- Cards may wrap lines every 4–5 groups. When a share is consumed, all
  whitespace and hyphens are stripped before decoding.
- A human-facing header line such as `RAVENVAULT SHARE i/k n=5` is
  **UI layer only — it is not part of the scanned or transcribed payload**.
  The payload itself is ASCII-clean (alphabet + hyphen) so it can be printed
  as a single QR alphanumeric-mode symbol.
- The complete printed payload (all groups, in order, separators included or
  stripped) is what decoders accept.

## 4. Integrity: CRC-32

The checksum is **CRC-32/ISO-HDLC** (the IEEE/zlib reflection-based CRC-32,
polynomial 0xEDB88320 reflected / 0x04C11DB7 normal, init and final xor
`0xFFFFFFFF`). Standard check value: the CRC of the ASCII string
`"123456789"` is `0xCBF43926`.

The checksum covers the version byte through the last value byte
(bytes `0…4+L`) and is appended big-endian.

**Error detection argument:** a single mis-copied base32 symbol changes at
most 5 adjacent bits of the byte string. CRC-32 with this parameter set
detects every burst error of length ≤ 32 bits, so every single-symbol
transcription error — and every adjacent-pair error (≤ 10 bits) — is caught
with certainty; two independent wrong symbols are caught with probability
1 − 2⁻³². Because the checksum covers the header too, a share cannot be
silently mis-attributed to a different index or secret.

A string that is not the canonical encoding of any byte string (§2.3) is
rejected exactly like a checksum failure: it is a mis-transcription.

## 5. Recovery procedure

The recovery order is normative. A decoder MUST:

1. **Normalize** — strip separators/whitespace, resolve case and aliases,
   validate symbols.
2. **Verify the CRC** of each share. A failure MUST abort with an explicit
   "share mis-transcribed" error. Corrupt shares MUST NOT be fed into
   Lagrange reconstruction: a silent wrong-secret reconstruction is the
   worst possible failure mode for a paper backup.
3. **Check headers agree** — all shares must carry the same
   `version` / `threshold` / `total`.
4. **Check indices are distinct** — a duplicated paper means two copies of
   one share, not two independent shares.
5. **Check the count** — at least `threshold` distinct shares must be
   present.
6. **Combine** — hand the distinct shares to the underlying GF(2^8)
   reconstruction.

## 6. Versioning

The first byte of the payload is the version. **The evolution promise is
additive-only:** a future format may define version `0x02` with a different
layout behind the same first-byte discriminator, but the meaning of every
`0x01` payload defined here is frozen permanently. Shares written as v1 must
decode as v1 forever.

## 7. Test vectors

Machine-readable vectors live at
[`Docs/TEST-VECTORS/shamir-paper-v1.json`](./TEST-VECTORS/shamir-paper-v1.json).
Each vector pins the secret, the exact share value bytes (share generation
is randomized, so the values are pinned rather than derived), and the exact
printed paper strings. A conforming implementation must reproduce the paper
strings byte-for-byte, decode them back to the pinned shares, reconstruct the
secret from any `threshold`-of-`total` subset of paper strings, and reject
every single-symbol corruption of every paper string.
