# Recommended target

I interpret **“EU wallet issuer”** as a **Credential Issuer that issues PID or electronic attestations into certified EUDI Wallet Units**—an ARF PID Provider, QEAA Provider, PuB-EAA Provider, or non-qualified EAA Provider. That is distinct from the **Wallet Provider**, which makes the certified Wallet Solution available. One organization may combine roles, but it must satisfy the legal and technical obligations of each role independently.  [oai_citation:0‡eu-digital-identity-wallet.github.io](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/2.9.0/architecture-and-reference-framework-main/)

The right product is therefore not a generic “VC minting service.” It is a **profile-locked, evidence-driven issuer**, where every production deployment identifies:

- issuer role and legal category;
- exact credential type and rulebook;
- OpenID/ARF compatibility profile;
- SD-JWT VC or mdoc format revision;
- subject-proofing and authentic-source policy;
- device-binding and Wallet Unit evidence policy;
- issuer registration, certificate, and trust-list policy;
- status, reuse, batch, reissue, privacy, and retention policy.

## Normative baseline

As of July 20, 2026, the implementation baseline should start with **ARF 2.9.0**, released May 11, 2026. The authoritative ARF high-level requirements are in the Annex 2 CSV; ARF explicitly says the CSV takes precedence over the generated Markdown if they differ. ARF is also explicit that it is informative and does not replace the binding Regulation and implementing or delegated acts, so the project needs both a technical requirement register and a legal-applicability register.  [oai_citation:1‡GitHub](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/CHANGELOG.md)

For issuance, ARF requirement `ISSU_01a` requires PID and Attestation Providers to support **OpenID4VCI as profiled by HAIP sections 4 and 6**, with the additions and changes made by ARF and Technical Specification 3.  [oai_citation:2‡eudi.dev](https://eudi.dev/2.9.0/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/)

The initial standards lock should contain:

| Layer | Version to pin |
|---|---|
| EUDI architecture | ARF 2.9.0 and an immutable Annex 2 HLR CSV snapshot |
| Issuance protocol | OpenID for Verifiable Credential Issuance 1.0 Final |
| High-assurance profile | OpenID4VC HAIP 1.0 Final |
| Wallet evidence | EC TS03 v1.5.2 |
| Credential semantics | Exact PID or Attestation Rulebook commit and digest |
| SD-JWT compatibility | SD-JWT VC draft-13 and Token Status List draft-14 for the HAIP 1.0 profile |
| mdoc compatibility | Exact ISO/IEC 18013-5 edition, rulebook, and ARF/HAIP profile |
| Issuer certificates | Exact applicable ETSI TS 119 412-6 version |
| EUDI issuance extensions | Exact applicable ETSI TS 119 472-3 version |
| Cryptography | Exact EUDI/ENISA algorithm-policy version |

This must be a lockfile, not documentation saying “latest.” OID4VCI 1.0 itself cites SD-JWT VC draft-11 and Token Status List draft-12, while HAIP 1.0 overrides those with draft-13 and draft-14 and explicitly directs implementations to continue using those revisions unless an updated profile says otherwise.  [oai_citation:3‡openid.net](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

TS03 v1.5.2 covers the transfer, format, content, lifecycle, and revocation of WIA and KA evidence used during PID and attestation issuance. It should be separately pinned and subjected to a recorded delta analysis against ARF 2.9.0 rather than assuming that all publication timelines align perfectly.  [oai_citation:4‡GitHub](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/issues/17)

## Architecture

The central design should be:

```text
 HTTP / JSON / JOSE / CBOR / COSE
                │
       strict wire adapters
                │
       typed validation evidence
                │
                ▼
 ┌─────────────────────────────────┐
 │     Pure verified Rust kernel   │
 │                                 │
 │  profile validation             │
 │  MayIssue predicate             │
 │  total transition function      │
 │  nonce/replay/idempotency state │
 │  credential semantic builder    │
 │  retention transitions          │
 └─────────────────────────────────┘
          │                 ▲
          │ refines         │ specification/proofs
          ▼                 │
        Lean 4 canonical semantics

          │
          ▼
 one-shot SignCredential capability
          │
          ▼
   transactional store + HSM

 Tamarin model spans Wallet, AS, Issuer, WIA/KA,
 trust sources, active network attacker and compromise.
```

### The critical boundary

Only the pure kernel may produce a `SignCredential` command. No HTTP handler, background worker, database callback, or HSM adapter may invoke credential signing through another route.

A signing capability should bind at least:

```text
session_id
request_id
profile_id
standards_manifest_digest
subject_evidence_digest
authorized_dataset_digest
holder_key_thumbprint
unsigned_credential_digest
algorithm
issuer_key_id
validity_interval
state_revision
one_time_command_id
capability_expiry
```

The database must atomically consume that capability together with the nonce, status reservation, and logical issuance record. This gives a precise implementation point for:

> No credential can be signed unless the verified decision kernel authorized that exact credential.

## Canonical formal predicate

The semantic center should be one predicate:

```text
MayIssue(state, request, now)
```

A representative definition is:

```text
MayIssue(s, r, now) :=
    session_is_open(s)
  ∧ profile_is_enabled_and_pinned(s.profile)
  ∧ issuer_is_operational(s.profile, now)
  ∧ issuer_is_registered_and_entitled(
        s.profile,
        r.credential_type,
        now)
  ∧ authorization_is_valid_for(
        s.authorization,
        r.configuration,
        r.dataset,
        now)
  ∧ access_token_is_valid(s.token, now)
  ∧ token_is_DPoP_bound_to(s.token, r.dpop_key)
  ∧ credential_endpoint_DPoP_is_valid(r, now)
  ∧ credential_proof_is_valid(
        r.proof,
        issuer_audience,
        expected_c_nonce,
        now)
  ∧ nonce_is_live_and_unused(s, expected_c_nonce)
  ∧ possession_proved_for_every_requested_holder_key(r)
  ∧ WIA_is_trusted_fresh_and_not_revoked(s.wallet, now)
  ∧ KA_is_trusted_fresh_and_not_revoked_when_required(
        s.wallet,
        r.holder_key,
        now)
  ∧ holder_key_satisfies_storage_and_algorithm_policy(r)
  ∧ subject_proofing_satisfies_issuer_role(s.subject, now)
  ∧ subject_has_right_to_receive(s.subject, r.credential_type)
  ∧ claims_are_authoritative_current_and_schema_valid(s.claims)
  ∧ requested_dataset_is_authorized(r, s.authorization)
  ∧ requested_validity_is_permitted(s.profile, now)
  ∧ expiry_does_not_exceed_WIA_KA_maintenance_periods(s, r)
  ∧ status_reservation_is_unique_and_live(r)
  ∧ batch_and_reuse_policy_holds(s, r)
  ∧ logical_issuance_is_idempotent(s, r)
  ∧ every_required_unique_value_is_fresh(r)
```

The only signing rule is then:

```text
MayIssue(s, r, now)
──────────────────────────────────────────────────── ISSUE
step(s, Issue(r, now))
  = Ok(s', [SignCredential(exact_payload, capability), ...])
```

For PID, ARF makes device binding mandatory, requires LoA High identity proofing, requires PID Rulebook compliance, and requires WIA/KA trust and revocation verification. For attestations, the applicable Rulebook remains mandatory; device binding is generally a `SHOULD`, becomes mandatory for mdoc, and a device-bound attestation requires KA/storage evidence. Attestation issuance must also validate the subject where applicable, the validity of attributes, and the requester’s right to receive the attestation.  [oai_citation:5‡eudi.dev](https://eudi.dev/2.9.0/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/)

The PID validity interval must not extend beyond the relevant WIA and KA revocation-maintenance periods. The same bound applies to attestations when revocation chaining is used.  [oai_citation:6‡eudi.dev](https://eudi.dev/2.9.0/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/)

## Protocol profile

For the HAIP issuance profile, implement at least:

- authorization-code flow;
- PKCE with `S256`;
- PAR where applicable;
- authorization-response issuer identification;
- DPoP sender-constrained access tokens and DPoP nonce handling;
- wallet authentication at PAR and token endpoints;
- same-device and cross-device Credential Offers;
- key attestations and proof of possession;
- strict scope-to-credential-type mapping;
- refresh tokens under a defined rotation, reuse-detection, and same-wallet policy.

HAIP mandates authorization-code support, the applicable FAPI 2.0 provisions, PKCE `S256`, PAR where applicable, and DPoP-bound access tokens. It also requires Credential Offers in both same-device and cross-device flows and wallet authentication at OAuth endpoints that support client authentication.  [oai_citation:7‡openid.net](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)

OpenID4VCI defines the mandatory Credential Endpoint and optional nonce, deferred, offer, and notification mechanisms. HAIP makes some otherwise optional capabilities mandatory for its profile. The Credential Endpoint may issue one credential or multiple credentials with the same configuration and dataset and may require possession or attestation of holder key material.  [oai_citation:8‡openid.net](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

OpenID4VP should be a separate module. It becomes part of the issuer only where an existing credential presentation is used as identity, entitlement, or claim-source evidence, or where the same deployment also operates as a Verifier. It should not be represented in Lean or Tamarin by an unexplained `presentation_valid : Bool`.

## WIA, KA, trust, and metadata

WIA validation cannot be treated as ordinary wallet client authentication. The issuer needs evidence covering:

- Wallet Provider trust through the applicable LoTE;
- Wallet Solution identity, version, and certification;
- Wallet Instance identity and status;
- WIA signature, validity, freshness, and revocation;
- KA signature and status where device binding applies;
- holder key covered by the KA;
- key-storage security properties;
- possession of every requested private key.

ARF requires issuer-side WIA verification under the OpenID4VCI Appendix E requirements and a check that the WIA has not been revoked. PID issuance must verify both WIA and KA and their referenced Wallet Instance and WSCD status. Attestation issuance always validates WIA; KA is additionally validated for device-bound attestations.  [oai_citation:9‡eudi.dev](https://eudi.dev/2.9.0/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/)

Issuer metadata should be generated from the active formal profile rather than hand-maintained. ARF requires PID and Attestation Providers to sign their Credential Issuer Metadata using the key corresponding to their access certificate and include the access certificate and intermediates in the JWS `x5c` header. Registration and entitlement evidence must also support verification that the provider is entitled to issue the declared type.  [oai_citation:10‡eudi.dev](https://eudi.dev/2.9.0/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/)

OpenID4VCI requires signed metadata to use JWS and the explicit `openidvci-issuer-metadata+jwt` type, with the Credential Issuer Identifier in `sub` and an issuance time in `iat`.  [oai_citation:11‡openid.net](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

## State model

Do not use one long enum such as `Authorized → TokenIssued → CredentialIssued`. Batch, retries, refresh, deferred issuance, and concurrent evidence resolution make that brittle.

Use an orthogonal state record:

```text
Session {
    lifecycle,
    profile,
    offer,
    authorization,
    token_binding,
    credential_proof,
    wallet_evidence,
    subject_evidence,
    claim_evidence,
    nonce_ledger,
    replay_ledger,
    request_states,
    status_reservations,
    logical_credentials,
    technical_credential_instances,
    retention_state,
    revision
}
```

Define a total function:

```text
step : State → Input → Except Error (State × List Output)
```

Every mutation increments a state revision. Requests carry an expected revision or an idempotency key. Ambiguous HSM/database timeouts are reconciled using the command ID and exact unsigned-credential digest; the runtime must never respond to uncertainty by blindly signing again.

## Lean proof obligations

Lean should be the canonical semantics rather than a prose copy of Rust. At minimum, prove:

| Property | Required result |
|---|---|
| Signing authorization | Every reachable signing command implies `MayIssue` for that exact request and state. |
| Authorization non-escalation | Issued type, configuration, format, and dataset are exactly authorized or an explicitly permitted subset. |
| Single use | Authorization codes, nonces, replay IDs, refresh rotations, status reservations, and signing capabilities cannot be consumed twice. |
| Token binding | The access-token confirmation key equals the key authenticated by the accepted DPoP proof. |
| Holder binding | Every device-bound credential has current possession and profile-required KA/storage evidence for the credential key. |
| Role soundness | Every PID satisfies PID-specific requirements; every EAA satisfies its selected legal category and Rulebook. |
| Validity | Credential expiry respects profile, source-evidence, WIA, KA, and revocation-maintenance bounds. |
| Batch correctness | Batch items have the required common dataset/format and distinct salts, indexes, holder keys where applicable, signatures, and identifiers. |
| Reissue binding | A device-bound logical credential cannot be reissued to another Wallet Unit except through an explicitly modeled rebinding ceremony. |
| Retention | Linkability values are absent from retained state after their deletion deadline. |
| State safety | All successful transitions preserve the global invariant. |
| Determinism and totality | `step` is deterministic and returns a typed result for every input. |
| Wire laws | Accepted semantic values round-trip; canonical encodings are injective where required. |
| Metadata consistency | Signed and unsigned metadata are derived from the same active profiles. |

Lean is appropriate for this canonical executable semantics and proof layer.  [oai_citation:12‡Lean Language](https://lean-lang.org/)

## Tamarin proof obligations

Tamarin should model the network as adversary-controlled and include unbounded, interleaved sessions. Its rules should separately model the Wallet Unit, Wallet Provider/WIA/KA issuer, Authorization Server, Credential Issuer, issuer access CA/registrar, authentic source, revocation/status source, and HSM. Tamarin is designed for symbolic security-protocol modeling with multiset-rewriting state, explicit attacker knowledge, and arbitrarily many concurrent protocol instances.  [oai_citation:13‡tamarin-prover.com](https://tamarin-prover.com/manual/master/book/001_introduction.html)

Required lemmas should include:

- injective agreement on issuer, wallet/client, subject, credential profile, dataset, and holder key;
- PKCE resistance to authorization-code interception;
- DPoP resistance to stolen-token use;
- nonce, DPoP proof, authorization code, and refresh-token replay resistance;
- no credential issuance without matching authorization and current WIA/KA evidence;
- no issuance after relevant revocation, under explicit status-freshness assumptions;
- resistance to QR/session swapping in cross-device issuance;
- credential unforgeability absent issuer-key compromise;
- same-wallet binding during refresh and reissue;
- secrecy of bearer values and subject data under stated endpoint-compromise assumptions;
- accountability lemmas identifying the minimal compromise set needed for unauthorized issuance;
- observational-equivalence goals for batch and issuer-side unlinkability.

Tamarin’s privacy proof does not cover IP addresses, TLS fingerprints, browser state, timing distributions, logs, or HSM queue timing. Those require separate data-flow controls and empirical testing.

## Rust verification approach

Use Rust for production, but keep the verified kernel in a deliberately restricted subset:

```rust
#![forbid(unsafe_code)]
```

Within that kernel, avoid:

- async and threads;
- I/O and network types;
- direct time or entropy access;
- global state and interior mutability;
- FFI;
- trait objects;
- unbounded recursive parsing;
- hidden panics and unchecked integer arithmetic.

Use explicit ports for time, entropy, signing, trust resolution, revocation, subject evidence, persistence, and audit output.

The preferred refinement path is:

1. Implement the decision kernel in restricted safe Rust.
2. Translate it to Lean using a pinned Aeneas/hax toolchain.
3. Prove the translated definitions refine the canonical Lean transition model.
4. Keep the translator itself in the declared trusted computing base unless independently validated.
5. Use differential vectors to ensure Rust wire encoders match the formally specified semantics.

Aeneas translates Rust programs into Lean for functional-correctness verification. Hax provides a Rust-to-Lean route through Aeneas using `cargo hax into lean`; because these toolchains are evolving, exact commits and supported Rust features must be locked.  [oai_citation:14‡Lean Language](https://lean-lang.org/use-cases/aeneas/)

Use **Verus** selectively for imperative Rust components whose invariants are awkward to express through extraction, such as bounded collection manipulation or transactional adapter logic. Use **Kani** for bounded checks of panic freedom, arithmetic overflow, parser limits, and any isolated unsafe or FFI code. Neither should become a second, divergent canonical specification.  [oai_citation:15‡verus-lang.github.io](https://verus-lang.github.io/verus/guide/)

## Privacy requirements

Privacy must be part of the state machine, not merely an operational policy.

ARF requires negligible collision probability for credential salts, attribute hashes, status identifiers or indexes, holder public keys where applicable, and signature values. It also requires providers to discard unique elements and timestamps once they are no longer needed and not communicate them unnecessarily. Batch timestamps must not reveal that credentials belong to the same batch.  [oai_citation:16‡eudi.dev](https://eudi.dev/2.9.0/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/)

Model retention as explicit transitions:

```text
NeededForProtocol
    → NeededForCommit
    → NeededForDefinedObligation
    → DeletionDue
    → Deleted
```

Logs, queues, traces, metrics, exception reports, and backups are part of this model. Raw authorization codes, tokens, nonces, WIA/KA tokens, disclosures, salts, full credential payloads, and stable subject identifiers should never enter general-purpose telemetry.

The profile must also define `credential_reuse_policy` and the selected ARF reuse method. ARF requires issuers to define a linkability-risk policy, advertise the reuse policy in metadata, support batch and reissue features, and verify that a reissued device-bound credential goes to the same Wallet Unit.  [oai_citation:17‡eudi.dev](https://eudi.dev/2.9.0/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/)

## Conformance and evidence

Every applicable requirement should have one machine-readable traceability row:

```text
requirement_id
source/version/section
normative level
issuer role and profile
formal interpretation
Lean definition and theorem
Tamarin lemma
Rust symbol
unit/property/fuzz test
OpenID conformance case
EUDI conformance case
operational evidence
status and rationale
```

A production release should fail when any applicable `SHALL` or `MUST` is unmapped. A `SHOULD` deviation requires a reviewed interoperability and security justification.

The OpenID Foundation conformance suite is open source and can be run locally, which makes it suitable as a pinned CI gate.  [oai_citation:18‡openid.net](https://openid.net/certification/about-conformance-suite/)

The EUDI Functional Conformance Assessment Framework should also be integrated, but its current documentation states that it is under active development and that individual releases may cover only subsets of the framework. It should therefore complement, not replace, the formal models and OpenID conformance suite.  [oai_citation:19‡conformance.eudi.dev](https://conformance.eudi.dev/latest/)

## Recommended first vertical slice

A strong first engineering profile is:

```text
Issuer role:             Non-qualified EAA Provider
Credential:              One concrete rulebook-defined attestation
Format:                  SD-JWT VC HAIP-1 compatibility profile
Binding:                 Device-bound
OAuth:                   Authorization code only
Authorization Server:    Integrated initially
Flows:                   Same-device and cross-device Credential Offer
Issuance:                Synchronous, one credential
Wallet evidence:         WIA + KA
Status:                  One pinned status profile
Signing:                 HSM-backed
```

This slice exercises the hard security path—PAR, PKCE, DPoP, wallet authentication, WIA, KA, holder-key possession, metadata signing, subject evidence, status reservation, and HSM capability consumption—without prematurely claiming PID status. Batch, deferred issuance, refresh/reissue, mdoc, and PID should be added by first extending Lean and Tamarin, then refining the Rust implementation.

## Specification bundle

I created a v0.1 starter bundle containing the detailed architecture, standards manifest, assurance case, threat model, requirement matrix, formal-model seeds, schema, and Rust kernel:

- [Download the complete specification bundle](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1.zip?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)
- [Formal specification](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1/FORMAL_SPEC.md?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)
- [Standards lockfile](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1/standards.lock.toml?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)
- [Requirements traceability matrix](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1/requirements/traceability.csv?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)
- [Lean 4 model seed](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1/formal/lean/EudiIssuer/Model.lean?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)
- [Tamarin model seed](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1/formal/tamarin/eudi_issuance.spthy?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)
- [Pure Rust issuer kernel](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1/rust/issuer-core/src/lib.rs?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)
- [Assurance case](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1/ASSURANCE_CASE.md?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)
- [Threat model](sandbox:/mnt/data/eudi-formal-issuer-spec-v0.1/THREAT_MODEL.md?_chatgptios_conversationID=6a5e27ff-25bc-83eb-befe-acf8f0b60d8d&_chatgptios_messageID=297415a6-7613-454f-a68d-ae06ee4c678e)

Bundle SHA-256:

```text
80fe99c4bf52be8d5f2095fb6e89d13715707b731d84299525bb1f8720da98cc
```

The TOML, JSON, and CSV artifacts were structurally validated. Lean, Tamarin, and Rust toolchains were not installed in the generation environment, so the included proof and implementation seeds have not yet been machine-checked; the first repository gate must pin those toolchains and compile/prove them before the artifacts are treated as assurance evidence.
