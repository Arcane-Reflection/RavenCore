# AGPL Commitment — the RavenVault dead man's switch

RavenVault is open core: the RavenCore engine is MIT-licensed from day one, while
the iOS app layer is proprietary. This document is the project's public,
mechanically verifiable maintenance commitment (the "dead man's switch"):

> **If no new release tag exists within 12 months of the most recent release tag
> in this repository, the complete application source is published under
> AGPL-3.0 in this repository.**

The trigger is anchored exclusively to **release tag dates** — anyone can decide
whether it has fired by comparing two git refs. There is no appeal to judgment:
no "active development" style language, no subjective continuity tests.

## No automation

We deliberately do **not** run an automated date check in CI. The commitment is
kept honestly by (a) the public promise on this page and (b) the release
checklist item in [`RELEASE.md`](./RELEASE.md) ("check AGPL trigger clock"),
which every release must pass. Anyone may independently verify compliance at any
time by listing this repository's release tags.

## Scope table

| Component | Path | License today | After the trigger fires |
|---|---|---|---|
| RavenCore engine | `Packages/RavenCore/` | MIT (immediately open source) | unchanged — MIT |
| RavenVault app layer | `Sources/RavenVault/`, `Tests/`, app project files | proprietary | AGPL-3.0, published in this repository |
| Vendored Argon2 (reference C) | `Packages/RavenCore/Sources/CArgon2/` | CC0 1.0 OR Apache-2.0 upstream — see [`Packages/RavenCore/Sources/CArgon2/UPSTREAM.md`](../Packages/RavenCore/Sources/CArgon2/UPSTREAM.md) | unchanged (upstream license) |
| BIP39 English wordlist | `Packages/RavenCore/Sources/RavenCore/Seed/Resources/bip39-english.txt` | MIT (bitcoin/bips, pinned `ce1862ac6bcffa1dd20aad858380e51e66e949ea`) | unchanged — MIT |
| Spec references (SeedQR, Crockford Base32) | cited in `Docs/` | attribution only — no code copied | attribution only |

## Publication commitment

When the trigger fires, the **complete application source** — the full app layer
included, everything needed to build and run RavenVault from source — is
published **in this repository** under **AGPL-3.0**. It is not behind a form, an
email request, or a separate paid repository.

## Amendments

This is a one-way promise: amendments may only tighten this commitment (shorten
the window, broaden the scope), never loosen it. Extending the window, scoping
the publication down, or replacing the objective tag-date trigger with anything
subjective would be a breach of this commitment, not an amendment of it.
