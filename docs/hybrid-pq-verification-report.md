# Hybrid-PQ verification report

Evidence date: 2026-07-31. Profile: `euwallet-hybrid-pq-v1` (experimental,
private, disabled by default, non-EUDI).

Reproduce the hybrid-specific evidence gate from a clean checkout:

```sh
tools/evidence/verify-hybrid-pq.sh
```

## Byte-level interoperability

The issuer's `HybridContextV1` and `HybridTBSV1` constructor implements the
contract frozen by EUWallet PR #100. It consumes the same three published
vectors, copied byte-for-byte with pinned SHA-256 checksums:

- positive `wallet-export-v1` TBS;
- cross-purpose `wallet-recovery-v1` TBS;
- unsupported `euwallet-hybrid-pq-v2` mutation.

The executable suite also covers the issuer purpose `test-sd-jwt-wrapper-v1`,
mandatory context bindings, both-valid acceptance, either-invalid rejection,
missing components, payload/disclosure/context mutation, logical-generation
mismatch, unsupported profile/version/purpose, duplicate/noncanonical/trailing
CBOR, size bounds, mandatory experimental framing, and standard-profile
isolation.

This proves TBS compatibility with the currently published EUWallet vectors.
The complete shared envelope plus ES256/ML-DSA signature-vector corpus remains
blocked on EUWallet issue #83 and is not claimed here.

## Tier 2 — Lean 4 semantic proofs

Toolchain pin: `formal/lean/lean-toolchain`. Local evidence run: Lean 4.32.2.
`lake build` passes with 13 theorem declarations and zero `sorry` or added
`axiom` placeholders.

Hybrid theorems:

- `authorizeHybridSign_sound` — a hybrid command implies both ordinary issuer
  authorization and `hybridAccept`;
- `hybrid_accept_requires_both_components` — both signatures must be present
  and valid;
- `hybrid_accept_same_tbs` — both components authorize the same expected TBS;
- `hybrid_accept_generation_agreement` — both keys share one non-zero logical
  generation;
- `classical_only_cannot_hybrid_accept`;
- `post_quantum_only_cannot_hybrid_accept`;
- `classical_downgrade_cannot_hybrid_accept`;
- `unsupported_profile_cannot_hybrid_accept`.

Lean proves these properties of the explicit semantic model. It does not prove
the network adapter, CBOR parser, Security.framework, AES-GCM, ES256, or
ML-DSA implementation correct. Rust conformance/adversarial tests connect the
named policy conditions to the executable boundary.

## Tier 3 — Tamarin symbolic protocol analysis

Local evidence run: Tamarin Prover 1.12.0 with Maude 3.5.1. All seven lemmas
in `formal/tamarin/eudi_issuance.spthy` verify; none are falsified or
incomplete. The four hybrid lemmas are:

- `hybrid_issuance_is_atomic`;
- `hybrid_components_sign_same_tbs`;
- `classical_component_removal_is_rejected`;
- `hybrid_generation_agreement`.

The Tamarin theory treats ES256 and ML-DSA-65 as independent perfect symbolic
signature primitives under a Dolev-Yao attacker. It proves protocol trace
properties within that abstraction, not computational post-quantum security,
side-channel resistance, primitive conformance, or external certification.

## Executable and dependency evidence

The Rust evidence is supplied by `hybrid_codec`, `hybrid_signer`, and
`pq_backend` unit tests plus the full workspace test/clippy/build gates. The
workspace and serial Keychain integration runs pass 30 tests in total (with no
ignored test left unexecuted across the two runs). The hybrid-specific gate
passes all six codec tests. The
dependency decision, SBOM delta, RustSec result, key-wrapping design, and
remaining qualification gates are recorded in
`docs/hybrid-pq-dependency-evidence.md`.

Landing-page counters and claims must be updated only after this report and the
underlying commands pass. They are evidence summaries, not proofs by
themselves.
