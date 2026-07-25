# EUDI Formal Credential Issuer

An evidence-led German EUDI Credential Issuer for PID, EAA and QEAA credentials
in SD-JWT VC and mdoc formats. The implementation combines a pure Rust signing
decision kernel, a macOS Keychain-backed development signer, Lean 4 safety
proofs, Tamarin protocol analysis, and a Lovable-connected issuance portal.

## Runnable Rust development service

The repository now contains an incremental Rust implementation in
`rust/issuer-service`. On macOS it keeps separate P-256 signing keys in the
login Keychain and performs signatures through Security.framework.

Run it locally:

```sh
cd rust
LISTEN_ADDR=127.0.0.1:18080 \
ISSUER_URL=http://127.0.0.1:18080 \
TLSN_TRUSTED_NOTARY_KEY=<hex-uncompressed-sec1-p256-public-key> \
RUST_LOG=issuer_service=info \
cargo run -p issuer-service
```

Run the issuance portal in another terminal:

```sh
cd WebIssuer
bun install
VITE_ISSUER_URL=https://issuer.advatar.systems bun run dev -- --host 127.0.0.1 --port 3000
```

Open `http://127.0.0.1:3000`. The portal requests a fresh, five-minute
OpenID4VCI credential offer for each QR code; it does not embed static offers.
The portal defaults to the deployed `https://issuer.advatar.systems` backend.
`VITE_ISSUER_URL` remains available for an alternate environment. HTTPS
Lovable origins and local development origins are accepted; other hosted UI
origins must be listed exactly in the issuer's comma-separated `CORS_ORIGINS`.

Implemented gates currently include issuer and authorization-server metadata,
signed issuer metadata, PAR, PKCE S256, one-shot authorization codes, DPoP
ES256 verification and replay detection, credential nonces, JWT credential
proof verification, the pure `authorize_sign` gateway, and Keychain-backed
SD-JWT VC signing for the German PID and learning-attestation development
profiles. The mdoc profiles use tagged issuer-signed items, namespace digests,
holder COSE key binding, an MSO, and a COSE Sign1 carrying a Keychain-bound
development document-signer certificate chain.

The learning-attestation development profile is available in independently identified and
PID-bound variants. The PID-bound variant verifies a selectively disclosed PID presentation,
matches it to the authoritative education subject, and requires a fresh PID-holder-key proof that
binds the PID issuer JWT to the new credential holder key. It then emits
`cryptographically_bound_to: eu.europa.ec.eudi.pid.1`. Holder/device binding remains a separate
policy in both variants.

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

## Verification snapshot

The following commands currently complete successfully:

```sh
cd formal/lean && lake build                 # 5 Lean theorems
cd ../tamarin && tamarin-prover eudi_issuance.spthy --prove  # 3/3 lemmas
cd ../../rust && cargo test --workspace       # 7 default tests pass
cargo test --workspace -- --ignored           # 2/2 Keychain integration tests pass on macOS
cargo clippy --workspace --all-targets -- -D warnings
cd ../WebIssuer && bun run lint && bun run build
```

The two ignored Rust tests create or access persistent Keychain material and
must be invoked explicitly on macOS when that side effect is intended.

## Hosting boundary

`WebIssuer` builds for Cloudflare and can be published through Lovable. The
current Rust signer cannot be moved unchanged to Supabase Edge Functions or a
Cloudflare Linux container: Supabase Edge Functions use Deno/TypeScript, and
this development issuer deliberately signs through macOS Security.framework.

The compatible no-HSM development topology is a Mac-hosted issuer exposed over
an authenticated Cloudflare Tunnel, with the frontend on Lovable/Cloudflare.
Supabase may provide durable application state, but it must not receive raw
private signing keys. A container deployment requires a separately reviewed
production key-provider implementation.

## Important status

This is a **formally analysed development issuer**, not a claim of external
certification. The included Lean model and Tamarin theory are machine-checked,
and the Rust and web suites above pass. Those results establish only their
explicit model, symbolic, and executable-test scopes. German authority/CAB
assessment, official conformance suites, production trust anchors, operational
assurance, and any legally required qualification remain certification gates.

The phrase “all code verified” must be made precise. The recommended production claim is:

> For the explicitly identified safe-Rust issuer kernel, every reachable signing command refines the pinned Lean transition model, and the model proves the listed safety invariants. The Tamarin model proves the listed symbolic protocol properties under its stated cryptographic, PKI, time, revocation, and compromise assumptions. Runtime adapters and infrastructure are covered by explicit contracts, bounded checks, fuzzing, conformance suites, and operational assurance.

## Intended role

Here, “wallet issuer” is interpreted as a **Credential Issuer / PID Provider / Attestation Provider that issues into an EUDI Wallet Unit**. It is not the Wallet Provider that supplies the Wallet Solution. A deployment must select one or more explicit issuer roles and credential rulebooks; there is no unconstrained “generic credential” production profile.
# VCIssuer

## TLSNotary development evidence

`POST /evidence-offers/tlsnotary` accepts
`{"artifact": <tlsn.notary-artifact.v1>}`. The service verifies the artifact's
ES256 signature against `TLSN_TRUSTED_NOTARY_KEY`, enforces a five-minute
freshness window and one offer per notary session, and returns
`credential_offer_uri`, `deep_link`, and `expires_in`. The authorization-code
flow carries the verified evidence through PAR, token exchange, and signing.

The resulting SD-JWT VC uses `vct=dev.advatar.tlsn.evidence.1`. It is
development web evidence only and must never be interpreted as PID, EAA, QEAA,
regulated KYC, or an accredited identity assertion.
