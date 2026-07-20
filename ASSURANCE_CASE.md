# Assurance Case Skeleton

## Top claim

**CLAIM FI-C0:** The released issuer profile issues a credential only when the selected ARF/OpenID/rulebook authorization and evidence predicates hold, produces bytes conforming to the pinned profile, and preserves the stated security and privacy properties under the documented assumptions.

This claim is intentionally narrower than “the whole system is mathematically perfect.” It is decomposed into claims with evidence and assumptions.

## Claim decomposition

| ID | Claim | Primary evidence |
|---|---|---|
| FI-C1 | The normative baseline is complete and immutable for the selected issuer role and credential profile. | Standards manifest, applicability review, requirement matrix, conflict register. |
| FI-C2 | The semantic decision kernel never authorizes signing unless all modeled preconditions hold. | Lean definitions and `FI-SAF-*` theorems. |
| FI-C3 | The Rust decision kernel refines the Lean semantics. | Aeneas/hax translation and Lean refinement proofs. |
| FI-C4 | The protocol resists the modeled active attacker and compromise cases. | Tamarin `FI-PROT-*` trace and equivalence lemmas. |
| FI-C5 | Wire encodings and endpoint behavior interoperate with the pinned OpenID/EUDI profiles. | Official vectors, differential tests, OIDF conformance, EUDI FCAF cases, multi-wallet tests. |
| FI-C6 | Cryptographic keys and operations enforce the modeled abstract signature/freshness assumptions. | Approved libraries/HSM, key ceremonies, algorithm policy, KATs, operational monitoring. |
| FI-C7 | Environmental evidence such as WIA/KA, registration, revocation, and subject data is trustworthy and fresh enough. | Trust contracts, signed evidence, freshness monitors, fail-closed tests, provider assurance. |
| FI-C8 | Privacy/retention obligations cover databases, logs, queues, metrics, traces, backups, and failure paths. | Lean deletion invariant, data inventory, deletion receipts, adversarial log tests, operational audit. |
| FI-C9 | The release can be reproduced and its evidence is bound to the exact deployed bytes/configuration. | Reproducible build, SBOM, provenance, signed assurance bundle, deployment attestation. |

## Assumption template

Every assumption has this structure:

```yaml
id: FI-A-XXX
statement: precise, falsifiable statement
scope: components/profiles affected
justification: why the proof/model needs it
owner: named team or external authority
monitor: signal and interval
detection_latency: bound
failure_behavior: fail closed / degrade / revoke / alert
validation_evidence: test, certificate, audit, or measurement
residual_risk: explicit
```

## Minimum assumptions to resolve

- **FI-A-001 — Cryptographic abstraction:** selected algorithms/libraries/HSM mechanisms implement the abstract signing, hashing, and freshness properties within the adversary/resources considered.
- **FI-A-002 — Entropy:** the entropy source meets the required unpredictability and independence bounds; fork/VM snapshot behavior is controlled.
- **FI-A-003 — Time:** wall clock and monotonic clock remain within the profile’s skew/rollback bounds.
- **FI-A-004 — Transaction store:** compare-and-swap/serializable transactions provide the exact atomicity used by nonce, code, status index, refresh token, and signing-capability consumption.
- **FI-A-005 — HSM command binding:** the HSM adapter signs only the exact digest and algorithm in a valid, unconsumed kernel capability.
- **FI-A-006 — Trust sources:** CA, trust-list, registrar, WIA/KA, and status signatures and roots are distributed securely.
- **FI-A-007 — Revocation freshness:** the revocation oracle’s evidence and failure behavior meet stated freshness bounds.
- **FI-A-008 — Subject evidence:** identity/entitlement/authentic-source evidence has the claimed assurance and provenance.
- **FI-A-009 — TLS/browser boundary:** endpoints, redirect URIs, origins, and TLS termination preserve the channel/authentication assumptions made in Tamarin.
- **FI-A-010 — Translation:** selected Rust-to-Lean translation faithfully represents the accepted Rust subset, or the translation result has sufficient independent validation.
- **FI-A-011 — Tool integrity:** Lean/Tamarin/SMT/compiler binaries and dependencies correspond to pinned, reviewed artifacts.
- **FI-A-012 — Operations:** deployment configuration is the profile/configuration whose digest is in the assurance bundle.

## Evidence binding

Every evidence file SHALL contain or be covered by a signed manifest with:

```text
source_commit
standards_manifest_digest
profile_digest
lean_toolchain_digest
rust_toolchain_digest
tamarin_toolchain_digest
binary_digest
configuration_digest
generation_time
builder identity/provenance
review approvals
```

A proof from one profile or source revision cannot be presented as evidence for another merely because the source code “looks similar.”
