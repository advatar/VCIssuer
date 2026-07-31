# Experimental hybrid-PQ dependency evidence

Review date: 2026-07-31.

## Decision

The experimental ML-DSA-65 backend uses `libcrux-ml-dsa` 0.0.10 with default
features disabled and only `std` plus `mldsa65` enabled.

Reasons:

- It implements the final FIPS 204 ML-DSA parameter sets.
- The project states that its portable arithmetic, NTT, serialization, and
  high-level algorithm code are formally verified with hax/F*.
- It is Apache-2.0 licensed and builds with this repository's Rust 1.97
  toolchain and macOS target.
- Its API accepts caller-provided key-generation and signing randomness, which
  this adapter obtains directly from the operating-system CSPRNG.

This is not a certification or production approval. The crate does not publish
an MSRV, this repository has not commissioned an independent audit of the
complete dependency/configuration, and NIST lists FIPS 204 errata for a future
revision. The profile therefore remains compile/runtime isolated,
development-only, and outside EUDI claims.

RustCrypto `ml-dsa` was not selected because its current documentation warns
that it has not been independently audited. No ML-DSA primitive is implemented
in this repository.

## Experimental SBOM delta

Direct additions:

| Package | Version | Purpose | License |
|---|---:|---|---|
| `libcrux-ml-dsa` | 0.0.10 | ML-DSA-65 key generation/sign/verify | Apache-2.0 |
| `aes-gcm` | 0.10.3 | PQ secret-key wrapping | Apache-2.0 OR MIT |
| `zeroize` | 1.9.0 resolved | plaintext secret clearing | Apache-2.0 OR MIT |

The authoritative transitive closure and checksums are pinned in
`rust/Cargo.lock`. `cargo tree -p issuer-service` is the reproducible
human-readable SBOM view for this development build.

`cargo audit` completed against 1,174 RustSec advisories. It reported no known
vulnerability and one allowed unmaintained-package warning,
`RUSTSEC-2026-0173` for target-specific `proc-macro-error2` 2.0.1. The package
does not appear in the active host dependency tree; it arrives through the
experimental dependency's target/build closure and remains a dependency-review
follow-up rather than a production acceptance.

## Evidence and remaining gates

- ML-DSA exact lengths are checked before backend invocation: public key 1952,
  secret key 4032, signature 3309 bytes.
- Key generation and randomized signing use `rand::rngs::OsRng`.
- Backend tests cover successful sign/verify, changed-message rejection, and
  malformed component lengths.
- Codec tests cover atomic AND acceptance, missing/invalid components,
  unsupported profiles/versions, payload/disclosure/context/generation
  mutation, duplicate/trailing/malformed/oversized CBOR, and downgrade input.
- Shared EUWallet vectors, independent cross-library vectors, KAT evidence,
  fuzzing, and external review remain open gates.
