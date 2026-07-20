# EUDI Formal Credential Issuer — specification seed v0.1

This bundle is a concrete starting specification for a Rust Credential Issuer that issues PID or electronic attestations into certified EUDI Wallet Units.

It deliberately separates four kinds of evidence:

1. **Normative traceability** — every applicable `SHALL`, `MUST`, `SHOULD`, profile choice, and rulebook rule is pinned and mapped.
2. **Semantic correctness** — a total issuer transition system and domain invariants are specified in Lean 4.
3. **Protocol security** — attacker-controlled network traces, compromise cases, replay, binding, and privacy-equivalence goals are modeled in Tamarin.
4. **Implementation conformance** — a small, pure Rust kernel refines the Lean model; wire adapters are checked with conformance tests, fuzzing, bounded model checking, and interoperability tests.

## Start here

- [`FORMAL_SPEC.md`](FORMAL_SPEC.md): architecture, protocol, state machine, proof obligations, and acceptance gates.
- [`standards.lock.toml`](standards.lock.toml): immutable standards/profile manifest. Production builds must fail while any required digest is blank.
- [`requirements/traceability.csv`](requirements/traceability.csv): seed requirements-to-evidence matrix. It is not yet exhaustive.
- [`formal/lean/EudiIssuer/Model.lean`](formal/lean/EudiIssuer/Model.lean): minimal Lean model and a first safety theorem.
- [`formal/tamarin/eudi_issuance.spthy`](formal/tamarin/eudi_issuance.spthy): minimal Tamarin security model.
- [`rust/issuer-core/src/lib.rs`](rust/issuer-core/src/lib.rs): pure Rust decision kernel mirroring the model.
- [`ASSURANCE_CASE.md`](ASSURANCE_CASE.md): assurance claims, assumptions, and trusted computing base.
- [`THREAT_MODEL.md`](THREAT_MODEL.md): threat inventory and required proof/test evidence.

## Important status

This is a **specification seed**, not a claim of certification or completed machine verification. The Lean, Tamarin, Aeneas/hax, and Rust toolchains were not available in the environment that generated this bundle, so the included starter models were not compiled or proved here. Pin exact tool versions and make clean CI builds mandatory before treating any theorem or lemma as evidence.

The phrase “all code verified” must be made precise. The recommended production claim is:

> For the explicitly identified safe-Rust issuer kernel, every reachable signing command refines the pinned Lean transition model, and the model proves the listed safety invariants. The Tamarin model proves the listed symbolic protocol properties under its stated cryptographic, PKI, time, revocation, and compromise assumptions. Runtime adapters and infrastructure are covered by explicit contracts, bounded checks, fuzzing, conformance suites, and operational assurance.

## Intended role

Here, “wallet issuer” is interpreted as a **Credential Issuer / PID Provider / Attestation Provider that issues into an EUDI Wallet Unit**. It is not the Wallet Provider that supplies the Wallet Solution. A deployment must select one or more explicit issuer roles and credential rulebooks; there is no unconstrained “generic credential” production profile.
# VCIssuer
