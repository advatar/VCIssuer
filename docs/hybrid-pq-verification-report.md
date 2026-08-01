# Hybrid-PQ verification report

Evidence date: 2026-08-01. Profile: `euwallet-hybrid-pq-v1` (experimental,
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
The issuer also matches the standalone public-key and atomic dual-signature
container bytes frozen by EUWallet PR #103, including their strict 8 KiB,
canonical-CBOR, closed-field, exact-component, and downgrade-rejection rules.

The shared component corpus adds one canonical issuer-wrapper TBS, real P-256
and ML-DSA-65 public keys, real signatures produced by VCIssuer's `p256` and
libcrux backends, both frozen component envelopes, and twelve deterministic
rejection mutations. EUWallet independently verifies the ES256 signature with
AWS-LC and the ML-DSA-65 signature with RustCrypto `ml-dsa`, then consumes the
same mutation instructions. Fixed seeds and randomness are public test fixtures
and are never production key material.

The credential wrapper carrying the canonical payload, disclosures, key
identifiers, generation, and both signatures is jointly frozen as
`HybridCredentialWrapperV1` by EUWallet issue #119. The shared wrapper corpus
consists of one positive wrapper envelope over the exact component-corpus
fixture — its committed TBS is byte-identical to the shared component TBS — and
twenty-one deterministic rejection mutations covering framing, version,
profile, purpose, format, payload, disclosure (including reordering), key-ID
and generation binding, invalid and removed component signatures, truncation,
trailing bytes, duplicate fields, and noncanonical encoding. VCIssuer generates
and verifies the corpus with its own codec; EUWallet decodes it with an
independently implemented strict deterministic-CBOR decoder and verifies both
signatures with independent AWS-LC ES256 and RustCrypto ML-DSA-65 backends.
Both repositories pin identical SHA-256 checksums. Key identifiers and the
generation field are not signed; both verifiers enforce the documented binding
rule against the trusted logical identity and the context generation.

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
workspace and local serial Keychain integration runs pass 34 tests in total
(with no ignored test left unexecuted across the two local runs). Interactive
Keychain tests are not run in the headless Actions session, where macOS denies
Security.framework UI access; CI instead retains the deployed Keychain signer
smoke check. The hybrid-specific gate passes all ten codec/vector tests,
including the shared wrapper-corpus generation, verification, and
mutation-rejection test. The
dependency decision, SBOM delta, RustSec result, key-wrapping design, and
remaining qualification gates are recorded in
`docs/hybrid-pq-dependency-evidence.md`.

Landing-page counters and claims must be updated only after this report and the
underlying commands pass. They are evidence summaries, not proofs by
themselves.
