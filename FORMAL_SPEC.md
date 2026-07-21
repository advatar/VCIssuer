# Formal Specification for an ARF/OpenID-Conformant EUDI Credential Issuer

**Document ID:** EUDI-FI-SPEC-0001  
**Version:** 0.1  
**Status:** architecture and formalization baseline  
**Production language:** Rust  
**Canonical semantic specification:** Lean 4  
**Adversarial protocol model:** Tamarin Prover

## 1. Purpose and interpretation

This specification defines a high-assurance service that issues a Person Identification Data credential (PID) or an electronic attestation of attributes into an EUDI Wallet Unit.

The term **issuer** in this document means an OpenID4VCI Credential Issuer acting as an OAuth resource server, and possibly also operating or co-locating an Authorization Server. In ARF terms it is one of:

- PID Provider;
- qualified electronic attestation of attributes provider (QEAA Provider);
- electronic attestation of attributes issued by or on behalf of a public-sector body provider (PuB-EAA Provider);
- non-qualified electronic attestation provider (EAA Provider).

A **Wallet Provider** is a different actor. This service consumes evidence about a Wallet Unit, Wallet Solution, WSCA/WSCD or keystore, but does not itself become the Wallet Provider merely by issuing credentials.

A production deployment SHALL select a concrete `IssuerRole` and one or more concrete `CredentialProfile`s. Every active profile SHALL identify an applicable rulebook, legal category, credential format, trust framework, subject-proofing policy, status mechanism, device-binding policy, algorithm suite, validity policy, and privacy/reuse policy.

## 2. Normative-source control

### 2.1 Normative manifest

Conformance SHALL be evaluated against an immutable manifest, `standards.lock.toml`. A human-readable reference to “latest” is never sufficient. Each source entry SHALL include:

- title and issuing body;
- exact version, date, tag, or immutable commit;
- canonical retrieval location;
- SHA-256 digest of the exact bytes used by the project;
- role/profile applicability;
- whether it is legally binding, ecosystem-normative, protocol-normative, informative, or test-only;
- known conflicts, errata, and supersession rules.

The build SHALL fail when an applicable source is unpinned, has a missing digest, or changes bytes without an approved manifest update.

### 2.2 Initial baseline

The initial baseline is:

| Layer | Pinned baseline | Project treatment |
|---|---|---|
| EUDI architecture | ARF 2.9.0, including the authoritative Annex 2 HLR CSV snapshot | Requirements source and architecture profile; preserve an immutable local snapshot and digest. |
| Issuance protocol | OpenID for Verifiable Credential Issuance 1.0 Final | Base issuance protocol. |
| High-assurance profile | OpenID4VC High Assurance Interoperability Profile 1.0 Final | Mandatory protocol/security profile where incorporated by ARF. |
| Wallet evidence | EC TS03 v1.5.2 (2026-05) | WIA/KA transfer, representation, lifecycle, and revocation. Perform an explicit delta analysis against ARF 2.9.0 because the publication dates are not identical. |
| Credential semantics | Applicable PID or Attestation Rulebook, pinned by immutable commit and content digest | Defines credential type, attributes, validation, issuance, status, and legal category. |
| SD-JWT profile | Compatibility profile `sd_jwt_vc_haip_1`: SD-JWT VC draft-13 and Token Status List draft-14 | These are the versions pinned by HAIP 1.0. Do not silently substitute newer drafts. |
| mdoc profile | Applicable ISO/IEC 18013-5 edition plus rulebook and ARF/HAIP constraints | Edition/license record must be controlled in the manifest. |
| Algorithms | HAIP mandatory minimums plus the current EUDI/ENISA cryptographic profile selected by the scheme | Algorithm identifiers are policy data, never hard-coded informal assumptions. |

ARF is an informative architecture document and does not replace binding Union law or implementing acts. The project SHALL therefore maintain a separate legal/applicability register. A formal theorem can establish consistency with a formalized requirement; it does not establish regulatory designation, conformity assessment, qualified status, or certification.

### 2.3 Version-drift rule

OpenID4VCI, HAIP, ARF, IETF drafts, ISO documents, ETSI specifications, and rulebooks evolve on different schedules. The implementation SHALL support **named, immutable compatibility profiles**. A profile is an indivisible tuple:

```text
ProtocolProfile =
  (oid4vci_version,
   haip_version,
   arf_version,
   ts03_version,
   credential_format_version,
   status_format_version,
   rulebook_version,
   algorithm_policy_version,
   trust_policy_version)
```

A profile SHALL be advertised only after its complete conformance suite passes. Negotiation SHALL never combine components from different profiles unless that exact combination is itself a registered, tested profile.

### 2.4 Conflict handling

A source conflict SHALL create a blocking `NormativeConflict` record containing:

- the two exact requirements;
- affected profiles and code;
- legal/technical analysis;
- the selected interpretation and authority for that selection;
- migration and interoperability impact;
- approval identities and timestamps.

No generic precedence rule may silently rewrite normative text. The selected profile may add constraints, but it SHALL NOT weaken an applicable `SHALL`/`MUST` without an explicit, externally justified exception.

## 3. Scope

### 3.1 In scope

- Credential Issuer Metadata, including signed metadata and issuer registration evidence required by the selected EUDI profile.
- Issuer-initiated and wallet-initiated authorization-code issuance.
- Same-device and cross-device Credential Offers.
- PAR, PKCE `S256`, authorization response issuer identification, DPoP-bound access tokens, and wallet client authentication/attestation as profiled by HAIP.
- Nonce issuance and credential key-proof validation.
- WIA and, where applicable, KA verification, trust-chain processing, freshness, lifecycle, and revocation checking.
- Subject identity/evidence validation and entitlement to receive the requested credential.
- SD-JWT VC and/or ISO mdoc issuance according to a named profile and rulebook.
- Batch issuance, deferred issuance, notification, refresh/re-issuance, and status where enabled by profile.
- Privacy controls for per-credential uniqueness, batch unlinkability, retention, logging, and reuse policies.
- Issuer access certificates, registration certificates/registry evidence, trust lists, and entitlement to issue the selected credential type.
- Formal refinement and conformance evidence.

### 3.2 Conditional scope

OpenID4VP is a separate presentation protocol. It becomes in scope only when the issuer uses an existing credential presentation as subject evidence, entitlement evidence, or step-up authentication, or when the same deployment also acts as a Verifier. That module SHALL have a separate protocol state machine and Tamarin theory; it SHALL NOT be smuggled into the issuance model as an opaque boolean.

### 3.3 Out of scope for the verified kernel

- HTTP server framework behavior;
- operating system, container runtime, network stack, and TLS implementation;
- database engine and distributed consensus implementation;
- HSM firmware and vendor client implementation;
- external authentic sources, registrars, CAs, trust-list providers, and revocation/status publishers;
- identity-proofing operator conduct;
- legal qualification and organizational certification.

These are not ignored. They are modeled as ports with explicit assumptions, monitored operational controls, and separate evidence.

## 4. Assurance architecture

### 4.1 Four linked models

The project SHALL maintain four synchronized artifacts:

1. **Normative model** — traceability entries and executable profile configuration derived from pinned standards.
2. **Lean semantic model** — types, total transition relation/function, invariants, encoders/decoders, and proof obligations.
3. **Tamarin protocol model** — network messages, trust setup, corruption events, freshness, revocation knowledge, and trace/equivalence properties.
4. **Rust implementation** — a small pure kernel plus effectful adapters, with a refinement path back to Lean.

No artifact is allowed to be merely illustrative in a release. Every released Rust symbol that can influence a signing decision SHALL be linked to a Lean definition/theorem or an approved environmental assumption.

### 4.2 Trusted computing base

The assurance case SHALL enumerate at least:

- Lean kernel and exact Lean/toolchain dependencies;
- Tamarin binary, backends, and proof scripts/oracles;
- Aeneas/hax translation pipeline and any unproved translation assumptions;
- SMT solver and proof checker where Verus or another SMT-backed verifier is used;
- Rust compiler, Cargo resolver, LLVM, linker, and target platform;
- cryptographic library implementations and CPU features;
- HSM, remote signing protocol, key ceremony, and operator quorum;
- entropy source and clock;
- TLS stack and reverse proxy;
- database transaction and durability guarantees;
- CAs, trust anchors, registrars, trust lists, authentic sources, and revocation/status services.

Each assumption SHALL have an owner, monitoring mechanism, failure behavior, and test or audit evidence.

## 5. Component architecture

### 5.1 Crates

```text
issuer-domain          Pure identifiers, profiles, evidence, sessions, errors.
issuer-policy          Total authorization and validity policy.
issuer-transition      Pure `step(state, input) -> result(state, outputs)`.
issuer-wire-oid4vci    HTTP/JSON wire types and strict parsing.
issuer-jose            JWS/JWT/DPoP/SD-JWT verification and construction adapters.
issuer-cbor-cose       Deterministic CBOR and COSE adapters.
issuer-format-sdjwt    SD-JWT VC profile encoder and disclosure plan.
issuer-format-mdoc     ISO mdoc issuer-signed item construction.
issuer-wua             WIA/KA semantic validation and TS03 profile.
issuer-trust           PKI, trusted-list, access/registration certificate semantics.
issuer-status          Status allocation, publication, and revocation lifecycle.
issuer-runtime         HTTP, database, queues, observability, configuration.
issuer-hsm             Narrow signing/attestation-key port.
issuer-conformance     Test vectors and profile-specific conformance harness.
```

The first three crates form the **verified decision kernel**. They SHALL:

- use safe Rust only (`#![forbid(unsafe_code)]`);
- avoid async, I/O, threads, global state, wall-clock access, randomness, environment variables, trait objects, FFI, and interior mutability;
- receive time, randomness-derived values, and validated evidence as explicit values;
- expose total functions returning typed errors;
- use bounded/validated collections where denial-of-service limits matter;
- be accepted by the selected Rust-to-Lean translation subset.

### 5.2 Ports

Effects enter only through capabilities with contracts:

```text
Clock.now() -> Instant
Entropy.fill(domain_separator, len) -> SecretBytes
Signer.sign(key_id, alg, exact_bytes) -> Signature
TrustResolver.resolve(anchor_set, chain, at_time) -> TrustResult
RevocationOracle.status(reference, at_time, freshness_bound) -> StatusEvidence
SubjectEvidenceProvider.resolve(authz_context) -> SubjectEvidence
TransactionalStore.transact(expected_revision, commands) -> CommitResult
AuditSink.append(redacted_event) -> AuditReceipt
```

A port result is not trusted merely because its Rust type says `Valid`. The adapter SHALL produce a verifiable evidence object containing source identity, exact inputs/digests, policy version, observation time, freshness deadline, result, and signature/provenance where available.

### 5.3 Command boundary

Only the pure kernel may emit a `SignCredential` command. Runtime code SHALL NOT call the HSM for credential signing through any other path. The HSM adapter SHALL require a kernel-generated authorization capability containing:

- session ID;
- profile ID and manifest digest;
- subject/evidence digest;
- holder-key digest;
- exact unsigned credential digest;
- validity interval;
- unique command ID;
- kernel state revision;
- expiration and single-use marker.

The store atomically consumes this capability when committing the credential record. This is the implementation point for “no signing without authorization” and exactly-once logical issuance.

## 6. Formal domain model

### 6.1 Primitive semantic types

All security-significant strings SHALL use distinct newtypes rather than interchangeable `String`s:

```text
IssuerId, AuthorizationServerId, WalletProviderId, WalletInstanceId,
CredentialConfigurationId, CredentialTypeId, RulebookId, ProfileId,
SubjectId, SessionId, AuthorizationCodeId, AccessTokenId, RefreshTokenId,
NonceId, DPoPKeyThumbprint, HolderKeyThumbprint, StatusIndex,
CertificateFingerprint, TrustAnchorId, EvidenceDigest, CredentialDigest.
```

Wire spellings are parsed into these types only after syntax, normalization, length, and profile constraints succeed.

### 6.2 Issuer roles

```text
IssuerRole ::= PID | QEAA | PublicBodyEAA | NonQualifiedEAA
```

Role-specific policy SHALL not be encoded as scattered conditionals. It is a closed profile value with proof obligations.

### 6.3 Credential profile

A `CredentialProfile` SHALL contain at least:

```text
profile_id
manifest_digest
issuer_role
credential_configuration_id
credential_type / vct / docType
rulebook_id + rulebook_digest
format = SdJwtVc | Mdoc
format_version
status_profile
algorithm_suite
issuer_trust_profile
device_binding = Required | Recommended | Forbidden
holder_key_requirements
subject_evidence_policy
claim_source_policy
claim_schema + selective-disclosure policy
validity_policy
batch_policy
reuse_policy
refresh/reissue policy
notification policy
retention policy
maximum wire sizes
```

Profile validation is itself a total function. An invalid profile prevents service startup.

### 6.4 Evidence

Evidence is immutable and time-bounded:

```text
Evidence a := {
  value: a,
  source: EvidenceSource,
  observed_at: Instant,
  valid_from: Instant,
  valid_until: Instant,
  freshness_until: Instant,
  policy_digest: Digest,
  input_digest: Digest,
  provenance: Provenance
}
```

Relevant evidence types include:

- OAuth authorization grant and authorized credential set;
- DPoP proof and token confirmation-key binding;
- credential key proof, nonce and audience binding;
- WIA validation and Wallet Instance revocation status;
- KA validation and WSCA/WSCD or keystore status;
- proof of possession for every requested holder public key;
- subject identity proofing and authentication context;
- right/entitlement to receive the credential;
- authentic-source claim snapshot;
- issuer registration/access-certificate entitlement;
- rulebook/profile validity;
- status-index reservation;
- cryptographic randomness provenance.

### 6.5 Session state

Avoid a fragile single linear enum. Issuance contains orthogonal facts and may involve retries, batch requests, deferred jobs, and refresh. The canonical state is a record:

```text
Session := {
  id: SessionId,
  revision: Nat,
  profile: ProfileId,
  lifecycle: Open | Completed | Rejected | Expired,
  offer: Option CredentialOfferState,
  authorization: Option AuthorizationEvidence,
  token: Option TokenEvidence,
  proof: Option CredentialProofEvidence,
  wallet: Option WalletEvidence,
  subject: Option SubjectEvidence,
  claims: Option ClaimEvidence,
  requests: Map RequestId RequestState,
  nonce_ledger: NonceLedger,
  replay_ledger: ReplayLedger,
  issue_records: Map LogicalCredentialId IssueRecord,
  retained: RetentionState
}
```

Every mutation increments `revision`. Inputs carry an expected revision or an idempotency key. Conflicting transitions fail closed.

### 6.6 Inputs and outputs

`Input` is a closed sum type such as:

```text
StartOffer | AcceptPar | RecordAuthorization | ExchangeCode | AcceptCredentialRequest
| AcceptBatchRequest | RecordWalletEvidence | RecordSubjectEvidence
| CompleteDeferredIssue | RecordNotification | Refresh | Reissue | Revoke | Expire
```

`Output` is a closed sum of pure commands:

```text
Persist | SendProtocolResponse | AllocateFresh | CheckTrust | CheckRevocation
| QuerySubjectEvidence | ReserveStatus | SignCredential | PublishStatus
| EmitRedactedAudit | DeleteRetainedValue
```

The transition kernel never performs an output. It returns commands to adapters. Adapter results re-enter as typed inputs.

## 7. Authorization-to-sign predicate

The canonical predicate is `MayIssue(state, request, now)`. It SHALL be true only when all applicable clauses are true:

```text
MayIssue(s, r, now) :=
  s.lifecycle = Open
  ∧ issuer_operational(s.profile, now)
  ∧ profile_enabled_and_pinned(s.profile)
  ∧ issuer_registered_and_entitled(s.profile, r.credential_type, now)
  ∧ authorization_valid_for(s.authorization, r.configuration, r.dataset, now)
  ∧ access_token_valid(s.token, now)
  ∧ token_is_DPoP_bound_to(s.token, r.dpop_key)
  ∧ request_DPoP_proof_valid(r, s.token, now)
  ∧ credential_proof_valid(r.proof, issuer_audience, expected_c_nonce, now)
  ∧ nonce_is_live_and_unused(s.nonce_ledger, expected_c_nonce)
  ∧ proof_of_possession_for_every_requested_holder_key(r)
  ∧ WIA_valid_trusted_fresh_and_not_revoked(s.wallet.wia, now)
  ∧ KA_valid_trusted_fresh_and_not_revoked_when_required(s.wallet.ka, now)
  ∧ holder_key_satisfies_profile_and_key_attestation(r.holder_key, s.profile)
  ∧ subject_proofing_satisfies_role(s.subject, s.profile, now)
  ∧ subject_has_right_to_receive(s.subject, r.credential_type, now)
  ∧ claims_are_current_authoritative_and_schema_valid(s.claims, s.profile, now)
  ∧ requested_claims_equal_or_are_subset_of_authorized_dataset(r)
  ∧ resulting_validity_is_permitted(s.profile, now)
  ∧ credential_expiry_not_after_WIA_KA_revocation_maintenance(s, r)
  ∧ batch_shape_and_reuse_policy_hold(s, r)
  ∧ status_reservation_is_unique_and_live_when_required(r)
  ∧ idempotency_and_exactly_once_constraints_hold(s, r)
  ∧ all_unique_elements_are_fresh_for_the_provider(r)
```

For a non-device-bound attestation profile, only the explicitly inapplicable KA/key-binding conjuncts may reduce to `True`; WIA validation remains applicable where ARF requires it. PID profiles require device binding.

The only rule capable of producing `SignCredential` is:

```text
MayIssue(s, r, now)
──────────────────────────────────────────────────────────── ISSUE
step(s, Issue(r, now)) = Ok(s', [SignCredential(payload, capability), ...])
```

## 8. Protocol state machine

### 8.1 Discovery and metadata

The issuer SHALL expose Credential Issuer Metadata at the standardized well-known location. The semantic metadata object SHALL be generated from active, validated profiles; hand-edited metadata is forbidden.

Where the EUDI profile requires signed issuer metadata:

- sign the exact canonical metadata payload under the selected JWS profile;
- use the required explicit media/type marker;
- bind the subject to the Credential Issuer Identifier;
- include issuance and optional expiry times;
- include the issuer access-certificate chain in the profile-required header parameter and validate chain construction rules;
- include registrar/registration evidence and `providesAttestations` information exactly as required by the active profile;
- prove/test that unsigned and signed metadata describe the same active configuration.

Metadata publication is a versioned state change. Removing a profile SHALL not invalidate in-flight sessions without an explicit migration/expiry rule.

### 8.2 Credential Offer

Both same-device and cross-device Credential Offer flows SHALL be supported for the HAIP profile. The offer state SHALL bind:

- issuer identifier;
- credential configuration IDs;
- offer ID and expiry;
- pre-authorized or authorization-code mode where allowed by the active profile;
- optional transaction code policy;
- redirect/session correlation value that is random and single use.

A QR code is attacker-visible. It SHALL contain no bearer secret whose theft alone authorizes issuance. Session swapping, duplicate scans, and race conditions SHALL be modeled.

### 8.3 Authorization request

For HAIP authorization-code issuance:

- use PAR where applicable and require wallet client authentication at PAR;
- require PKCE with `S256`;
- use `scope` values that map unambiguously to concrete credential types/configurations;
- bind request URI, client/wallet identity, redirect URI, issuer, state, code challenge, authorization details/authorized dataset, and expiry;
- return and validate authorization-server issuer identification;
- issue short-lived, single-use authorization codes.

The authorization result SHALL contain a normalized `AuthorizedCredentialSet`; free-form OAuth scopes SHALL never be checked later by string-prefix or substring logic.

### 8.4 Token endpoint

The token endpoint SHALL:

- authenticate the wallet according to the selected HAIP client-attestation profile;
- validate code, redirect URI, issuer, client identity, PKCE verifier, expiry, and single use atomically;
- issue DPoP sender-constrained access tokens;
- record the DPoP public-key thumbprint in token evidence;
- implement DPoP replay protection and nonce behavior;
- issue refresh tokens only under an explicit profile, rotate them, detect reuse, and bind them to the same wallet/logical credential context.

A token is authorization evidence, not permission to issue arbitrary metadata. The credential endpoint still validates exact authorized configurations/datasets and proof/key evidence.

### 8.5 Nonce and credential proof

Nonce records SHALL contain issuer, session/token context, intended proof type, issue time, expiry, use count, and random identifier. Consumption and issuance commit SHALL be atomic.

The proof verifier SHALL validate the exact profile requirements, including:

- supported proof type and algorithm;
- protected-header semantics and critical parameters;
- signature over exact received bytes;
- issuer/audience binding;
- nonce binding;
- time bounds;
- holder key syntax and curve;
- proof of possession;
- key-attestation binding where required;
- no duplicate JSON members or ambiguous encodings.

A batch request SHALL prove possession of every requested holder key. One proof or key attestation may cover multiple keys only where the pinned profile explicitly permits it and the covered key set is cryptographically bound without ambiguity.

### 8.6 WIA and KA validation

The WIA/KA subsystem SHALL implement the pinned TS03 and ARF profile, including:

- transfer and exact representation;
- integrity/signature verification;
- certificate/trust-anchor and trust-list validation;
- Wallet Solution identity, version, certification, and Wallet Instance identity;
- issuance and expiry time;
- status/revocation reference and fresh status resolution;
- KA-to-holder-key and WSCA/WSCD/keystore binding;
- proof of private-key possession;
- algorithm and key-storage properties;
- policy for remote HSM architecture where applicable.

Validation results SHALL retain only the evidence needed to justify issuance and later obligations. Raw linkable WIA/KA values SHALL be deleted when no longer required by the pinned policy.

### 8.7 Subject and claim evidence

The subject subsystem SHALL distinguish:

- authentication of the current user;
- identification/identity proofing of the credential subject;
- representation/delegation;
- entitlement to receive the credential;
- authoritative source of every claim;
- claim freshness;
- evidence assurance level.

For PID issuance, the identity-proofing result SHALL meet LoA High requirements. Claims SHALL be constructed only from an approved, versioned source mapping. User-supplied strings cannot become authoritative claims merely because the user was authenticated.

### 8.8 Credential construction

An attestation profile SHALL state independently whether holder/device binding is required and
whether cryptographic binding to an existing PID or attestation is required. For a PID-bound
profile the issuer SHALL verify a fresh presentation of the existing PID, match its subject to the
authoritative subject of the new attestation, and verify a proof by the existing PID holder key
covering the PID issuer-signed JWT, issuer audience and nonce, and the new holder key. A missing,
stale, replayed, mismatched, or uncommitted disclosure SHALL fail closed. If the applicable
Rulebook uses it, the issued attestation SHALL carry `cryptographically_bound_to` with the exact
PID attestation type. A profile without cross-attestation binding SHALL reject unsolicited binding
evidence and SHALL NOT claim `cryptographically_bound_to`.

Credential construction SHALL be a pure function of:

```text
(profile, issuer identity, subject/claim evidence, holder key,
validity interval, status reservation, fresh unique values, exact issuance context)
```

It SHALL output an unsigned semantic credential and the exact bytes-to-sign. The signer returns a signature over those exact bytes. The system SHALL never parse and reserialize a signed object to decide what was signed.

### 8.9 Batch issuance

A batch request SHALL satisfy all base authorization requirements plus:

- every item maps to the same permitted format/dataset where required by OpenID4VCI/HAIP;
- every requested holder key has valid possession/key-attestation evidence;
- per-credential salts, hashes, status identifiers/indexes, signatures, and other unique values are independently fresh;
- timestamps and ordering do not create avoidable linkability;
- partial failure behavior is explicit and atomicity is profile-defined;
- response ordering does not leak stable wallet internals.

### 8.10 Deferred issuance and notification

A deferred transaction identifier is a high-value bearer/correlation value. It SHALL be random, scoped, expiring, access-token protected, replay-controlled, and stored as a digest where possible.

A deferred worker SHALL re-evaluate time-sensitive evidence before signing. It may not rely on a historical `MayIssue = true` bit after WIA/KA, subject evidence, registration, or policy validity has expired.

Notification identifiers SHALL not be reused across credentials or exposed in logs. Notification processing SHALL be idempotent.

### 8.11 Refresh and re-issuance

A re-issued device-bound credential SHALL be issued to the same Wallet Unit/logical holder context required by ARF. The model SHALL distinguish:

- a logical credential;
- technical credential instances;
- refresh authorization;
- current holder key and Wallet Instance evidence.

Refresh token theft SHALL not permit migration to another wallet or key. A key change requires a profile-defined re-binding ceremony and fresh WIA/KA/possession evidence.

### 8.12 Revocation and status

Status allocation SHALL be race-free and uniqueness-preserving. Status publication SHALL have explicit freshness/service-level guarantees. The credential validity interval SHALL respect the ability to maintain WIA/KA revocation status for the full credential lifetime where ARF requires that bound.

Issuer signing-key compromise, issuer authorization withdrawal, Wallet Provider/Wallet Solution withdrawal, Wallet Instance revocation, WSCA/WSCD revocation, credential revocation, and authentic-source correction are distinct events with distinct consequences.

## 9. Lean 4 specification and proof obligations

### 9.1 Canonical model

Lean is the canonical semantics, not a prose shadow of Rust. Definitions SHALL cover:

- profile validity and applicability;
- all semantic domain types;
- strict parser result types and normalization;
- `MayIssue`;
- total `step` function;
- state invariants;
- exact credential semantic construction;
- retention/deletion transitions;
- abstract cryptographic interfaces and assumptions.

### 9.2 Required safety theorems

At minimum, releases SHALL prove:

| Theorem ID | Property |
|---|---|
| `FI-SAF-001` | Any reachable `SignCredential` command implies `MayIssue` held for the same state, request, time, profile, subject, and holder key. |
| `FI-SAF-002` | An issued credential configuration/type and claim dataset are equal to or a permitted subset of the normalized authorization grant. |
| `FI-SAF-003` | A consumed authorization code, nonce, DPoP replay identifier, status reservation, and signing capability cannot be successfully consumed twice. |
| `FI-SAF-004` | The access token confirmation key equals the key authenticated by the credential-endpoint DPoP proof. |
| `FI-SAF-005` | Every device-bound credential is bound to a holder key with current possession evidence and the profile-required valid KA/storage evidence. |
| `FI-SAF-006` | Every issued PID satisfies the PID role, rulebook, device-binding, and subject-proofing invariants. |
| `FI-SAF-007` | Every issued attestation satisfies its selected legal category and applicable rulebook. |
| `FI-SAF-008` | Credential expiry does not exceed profile limits or applicable WIA/KA revocation-maintenance end times. |
| `FI-SAF-009` | Batch items satisfy the common dataset/format constraints and have distinct required cryptographic values. |
| `FI-SAF-010` | A device-bound re-issued technical credential remains bound to the same permitted Wallet Unit/logical credential context. |
| `FI-SAF-011` | No forbidden linkability value remains in retained state after its deletion boundary. |
| `FI-SAF-012` | State invariants are inductive under every successful transition. |
| `FI-SAF-013` | `step` is deterministic and total for all modeled inputs. |
| `FI-SAF-014` | Semantic encode/decode round trips hold for accepted values; canonical encodings are injective within the selected profile. |
| `FI-SAF-015` | Signed and unsigned issuer metadata are generated from the same active profile set. |
| `FI-SAF-016` | No runtime command can select a signing algorithm/key outside the active algorithm and issuer-key policy. |

### 9.3 Liveness and availability

Do not hide availability claims inside safety theorems. Liveness depends on fairness and external services. State explicit conditional properties such as:

> Given a live, authorized session; valid fresh evidence; available transactional store, trust/status services and HSM; and fair retry scheduling, the issuer eventually returns a credential or a terminal typed error.

Prove what is meaningful in Lean and monitor the environmental premises operationally.

### 9.4 Rust refinement

The preferred refinement path is:

1. write the verified kernel in a deliberately restricted safe-Rust subset;
2. translate it with a pinned Aeneas/hax pipeline to Lean;
3. prove the translated Rust definitions refine or are observationally equivalent to the canonical Lean model;
4. treat translator correctness as an explicit TCB assumption unless independently validated;
5. compare serialized test vectors from Lean/reference encoders and Rust adapters.

Before committing to Aeneas or hax, complete a bounded engineering spike using the hardest anticipated data structures, result types, map updates, and encoding logic. Select one primary extraction/refinement pipeline; do not maintain two divergent canonical specifications.

Verus is suitable for localized imperative invariants that are awkward to extract, but a Verus contract must link to the same semantic requirement. Kani is suitable for bounded, bit-precise checks of parser edges, integer overflow, panic freedom, and any isolated FFI/unsafe adapter. Neither substitutes for the Lean state-machine proof or Tamarin protocol proof.

## 10. Tamarin security model

### 10.1 Model scope

Tamarin SHALL model an active Dolev–Yao adversary controlling the network, with unbounded interleaved sessions. Model separate roles for:

- Wallet Unit;
- Wallet Provider/WIA and KA issuer;
- Credential Issuer;
- Authorization Server;
- issuer access CA/registrar/trust-list source;
- authentic claim source;
- status/revocation source;
- HSM/signing key.

Use explicit compromise rules and time/order events. TLS may be abstracted as authenticated confidential channels only when endpoint compromise, redirect/browser boundaries, and message origin are modeled separately. Otherwise, model the relevant application messages over the attacker network.

### 10.2 Required trace properties

| Lemma ID | Property |
|---|---|
| `FI-PROT-001` | Issuance event implies prior matching authorization for issuer, wallet/client, profile, subject/dataset, and holder key. |
| `FI-PROT-002` | Injective agreement between issuer and wallet on issuer ID, session, credential type, holder key, and authorized dataset. |
| `FI-PROT-003` | PKCE prevents authorization-code interception from producing a token absent wallet/client compromise. |
| `FI-PROT-004` | DPoP prevents use of a stolen access token without the bound key, subject to key compromise. |
| `FI-PROT-005` | Credential proof nonce and DPoP replay controls prevent accepted replay. |
| `FI-PROT-006` | A credential accepted as issuer-signed was produced by the issuer/HSM unless its signing key was compromised. |
| `FI-PROT-007` | A valid device-bound issuance agrees on the holder key covered by current WIA/KA/possession evidence. |
| `FI-PROT-008` | No issuance occurs after relevant revocation knowledge is required to be fresh, unless the revocation/status authority or checking assumption is compromised. |
| `FI-PROT-009` | Cross-device offer/QR session swapping does not cause issuance to an attacker-selected wallet/key. |
| `FI-PROT-010` | Refresh/re-issuance cannot move a device-bound logical credential to a different Wallet Unit/key without the profile-defined re-binding event. |
| `FI-PROT-011` | Authorization code, access token, refresh token, nonce secret (where secret), transaction ID, and subject claim data remain secret under stated endpoint-compromise assumptions. |
| `FI-PROT-012` | Accountability events identify the minimum compromised/trust-failure set when an unauthorized credential is issued. |

### 10.3 Privacy/equivalence goals

Use observational-equivalence/diff-equivalence models for:

- two batch credentials being swapped between otherwise equivalent issuance worlds;
- two wallets receiving equivalent claim sets with independent fresh values;
- retention deletion preventing later issuer-side correlation through protocol identifiers;
- status allocation strategies and their linkability surface.

A symbolic unlinkability proof is not a claim about IP addresses, TLS fingerprints, browser state, timing distributions, HSM queue timing, or logs. Those channels require architectural controls and empirical tests.

## 11. Wire and cryptographic rules

### 11.1 Strict parsing

Wire adapters SHALL reject rather than repair:

- duplicate JSON object member names;
- invalid UTF-8, invalid Unicode normalization where constrained, or prohibited control characters;
- non-canonical or malformed base64url;
- unknown or unsupported critical JOSE/COSE parameters;
- `alg = none`, symmetric algorithms where asymmetric signing is required, algorithm/key mismatch, or disallowed curves;
- malformed, overlong, recursive, or resource-exhausting JSON/CBOR;
- duplicate CBOR map keys and profile-forbidden non-deterministic encodings;
- ambiguous issuer, audience, redirect, origin, or URL normalization;
- certificate chains with profile-forbidden root inclusion, ordering, EKU, policy, name, validity, or trust-anchor behavior;
- proof objects that are syntactically valid but not explicitly supported by the active compatibility profile.

Use semantic types after parsing. Verification SHALL be performed over the exact received protected bytes, not a reconstructed equivalent object.

### 11.2 Cryptographic implementation

Do not implement primitive cryptography. Use audited libraries or HSM mechanisms behind a narrow adapter. The algorithm registry SHALL define:

- allowed signature, hash, key-agreement, and certificate algorithms;
- minimum key/curve parameters;
- protected header requirements;
- key usage separation;
- issuer key activation/retirement intervals;
- algorithm deprecation and emergency disablement;
- test vectors and negative vectors.

Randomness requests SHALL include a domain separator and minimum entropy length. Unique values SHALL be independently generated unless a formally justified deterministic construction is used with a secret PRF key and domain separation.

### 11.3 SD-JWT VC

For each pinned SD-JWT profile specify and prove/test:

- exact draft/final syntax;
- `vct`, issuer, temporal, confirmation/key-binding, status, and rulebook claims;
- disclosure plan and non-disclosable claims;
- salt length and generation;
- digest algorithm and digest placement;
- decoy policy if used;
- key-binding JWT requirements;
- issuer certificate-chain/profile rules;
- compact serialization and delimiter behavior;
- prevention of disclosure confusion, digest substitution, and claim-name collision.

### 11.4 ISO mdoc

For each mdoc profile specify and prove/test:

- exact ISO edition and document type;
- namespaces, data element identifiers, and rulebook mappings;
- deterministic CBOR profile where required;
- MSO and issuer-signed item construction;
- digest ID allocation and uniqueness;
- device key and device authentication binding;
- COSE protected headers, algorithms, and certificate chain;
- validity information and status/revocation integration;
- cross-format semantic equivalence for credentials that must be offered in both formats.

## 12. Privacy, retention, and observability

### 12.1 Data classes

Classify every field as:

- public configuration;
- operational metadata;
- personal data;
- special-category/sensitive claim data;
- bearer secret;
- cryptographic key material;
- linkability handle;
- audit evidence;
- derived digest.

A field without a class and retention rule is a build error in schema generation.

### 12.2 Minimize linkability

Per-credential salts, hashes, status identifiers/indexes, holder keys where newly generated, signature randomness/values, notification IDs, and similar unique elements SHALL have negligible collision probability across the provider’s issuance population.

For batch issuance, do not use common timestamps or sequential identifiers where they make credentials linkable beyond profile necessity. Timestamp precision SHALL be the minimum allowed by the profile.

### 12.3 Retention transitions

The Lean state includes deletion obligations. A value moves through:

```text
NeededForProtocol -> NeededForCommit -> NeededForDefinedObligation -> DeletionDue -> Deleted
```

The adapter returns a deletion receipt or a typed failure. A release SHALL define behavior when deletion cannot be confirmed. Logs, traces, metrics, crash reports, and queues are part of retention scope.

Never log raw:

- authorization codes, access/refresh tokens, transaction IDs, or DPoP proofs;
- credential proof nonces;
- WIA/KA tokens or stable identifiers;
- SD-JWT disclosures/salts or full credential payloads;
- mdoc issuer-signed items;
- subject identifiers or claim values unless a separately approved audit requirement demands them.

Use per-environment redaction keys and short-lived correlation identifiers that cannot reconstruct a credential.

## 13. Failure semantics

Every failure SHALL be typed and mapped to:

- protocol error response permitted by the pinned profile;
- retryability;
- whether evidence/session state changes;
- audit category;
- user-safe message;
- security alert severity.

Fail closed for uncertainty about trust, revocation freshness, profile applicability, authorization dataset, proof/key binding, clock bounds, uniqueness reservation, or transaction outcome.

After an ambiguous database/HSM timeout, do not simply sign again. Reconcile by command ID and exact unsigned-payload digest. The system SHALL distinguish “not committed,” “committed,” and “outcome unknown.”

## 14. Operational security requirements

- HSM keys SHALL be role-, environment-, profile-, and algorithm-separated.
- Key ceremonies SHALL establish provenance, quorum, backup/recovery, activation, retirement, destruction, and incident behavior.
- Clock synchronization and monotonicity assumptions SHALL be monitored. Backward jumps fail closed for issuance windows.
- Trust lists, CRLs/status lists, OCSP where applicable, registrar evidence, and authentic-source evidence SHALL have freshness budgets and stale-data behavior.
- Configuration and standards manifests SHALL be signed and promoted through separation of duties.
- Production SHALL use reproducible/hermetic builds, locked dependencies, SBOM, provenance attestations, vulnerability policy, and rollback artifacts.
- No network egress is permitted from the pure kernel; runtime egress is allow-listed by purpose.
- Secrets SHALL not enter developer telemetry or generic exception tracking.
- Rate limits SHALL be per endpoint and per semantic resource without creating stable cross-issuer tracking identifiers.

## 15. Traceability and conformance

### 15.1 Requirement record

Every applicable requirement SHALL have a row with:

```text
requirement_id, source, version, section, normative_level, role,
profile, interpretation, component, formal_definition,
lean_theorem, tamarin_lemma, rust_symbol, unit_test,
property_test, fuzz_target, conformance_case, operational_evidence,
status, reviewer, rationale
```

A requirement may be `NotApplicable` only with a reviewed role/profile rationale. `SHOULD` deviations require a written security/interoperability justification.

### 15.2 CI release gates

A release pipeline SHALL run, in order:

1. standards manifest digest and applicability validation;
2. exhaustive requirement-matrix validation;
3. Lean build with no `sorry`, untrusted axioms allow-list only, and proof artifact archive;
4. Rust-to-Lean extraction/refinement build;
5. Tamarin proofs with no remaining unproved required lemma and proof artifact archive;
6. Rust formatting, linting, dependency/license/security policy;
7. unit and property tests;
8. parser/encoder differential tests and official vectors;
9. cargo-fuzz/libFuzzer targets with saved corpus and sanitizer jobs;
10. Kani and/or Verus jobs for designated components;
11. OpenID Foundation conformance suite for every advertised OID4VCI/HAIP profile;
12. EUDI functional-conformance cases applicable to the role/profile as the framework matures;
13. negative interoperability tests against at least two independent Wallet implementations or designated reference implementations;
14. reproducible-build comparison, SBOM, provenance, and signed release evidence;
15. deployment-policy and key/trust configuration validation.

A protocol test suite proves observed behavior for selected cases; it does not replace semantic or adversarial proofs. Conversely, a theorem over an abstract model does not prove byte-level interoperability.

### 15.3 Evidence bundle

Each release SHALL emit an immutable assurance bundle containing:

- source commit and dirty-state proof;
- `standards.lock.toml` and all vendored source digests;
- active profile JSON and digest;
- requirement matrix;
- Lean toolchain/dependency lock and proof logs;
- Rust-to-Lean translation output and refinement proofs;
- Tamarin version, model, oracles, lemmas, and proof reports;
- test/conformance reports and exact suite versions;
- fuzz corpus digest and coverage summary;
- Kani/Verus reports;
- dependency lock, SBOM, licenses, vulnerability decision log;
- reproducible build digests;
- HSM key/certificate identifiers without secret material;
- reviewer approvals and residual-risk register.

## 16. Initial formal development plan

### Stage 0 — profile decision

Select one issuer role and one credential rulebook. Decide whether the Authorization Server is integrated or external, which Wallet client-attestation trust model is used, which HSM architecture is used, and which format is first.

For a first engineering slice, SD-JWT VC is often a smaller semantic/wire surface than simultaneous SD-JWT and mdoc. A PID Provider, however, must plan for the PID rulebook’s required format support; an mdoc-only rulebook changes that choice.

**Exit:** signed profile charter and no unresolved applicability questions.

### Stage 1 — normative extraction

Vendor pinned sources, compute digests, import the authoritative ARF HLR CSV, and produce the complete applicability matrix. Treat prose notes and cross-references as structured review items, not discarded commentary.

**Exit:** every applicable `SHALL`/`MUST` and every justified `SHOULD` has an owner and planned evidence.

### Stage 2 — semantic kernel

Formalize profile validity, evidence, session state, `MayIssue`, `step`, retention, and signing capabilities in Lean. Prove inductive safety before implementing network code.

**Exit:** `FI-SAF-001` through at least `FI-SAF-013` for the minimal synchronous, single-credential flow.

### Stage 3 — protocol model

Model issuer-initiated and wallet-initiated authorization-code flow, PAR/PKCE/DPoP, credential proof, WIA/KA, and issuance in Tamarin. Add compromise cases before claiming the happy-path lemmas.

**Exit:** required trace lemmas for the minimal profile and explicit unresolved privacy goals.

### Stage 4 — Rust refinement slice

Implement only the pure decision kernel. Complete the Aeneas/hax translation and prove refinement. Keep all I/O mocked as evidence values.

**Exit:** no Rust path to `SignCredential` outside the refined kernel.

### Stage 5 — strict wire adapters and one format

Implement metadata, offers, PAR/token/nonce/credential endpoint, strict JOSE parsing, WIA/KA adapter, and one credential format. Add official and adversarial vectors.

**Exit:** OpenID conformance for the selected profile, parser fuzzing, and byte-level golden vectors.

### Stage 6 — production effects

Add transactional store, HSM, trust lists/registrars, revocation/status, authentic sources, retention jobs, observability, and incident controls. Every adapter contract becomes an assurance-case assumption with evidence.

**Exit:** end-to-end assurance bundle in a non-production environment.

### Stage 7 — batch, deferred, refresh/reissue, second format

Extend Lean and Tamarin first, then Rust. Do not generalize the state machine after implementation without proof migration.

**Exit:** privacy and replay properties, conformance, and cross-format semantic tests for each enabled capability.

## 17. Release acceptance criteria

A production profile is releasable only when:

- all normative sources are immutable and digested;
- no unresolved normative conflict applies;
- the requirements matrix is complete for the selected role/profile;
- Lean contains no `sorry` in the trusted proof closure and all required theorems pass;
- Rust refinement passes for every signing-influencing kernel function;
- all required Tamarin lemmas are proved under reviewed assumptions;
- no unsafe code exists in the kernel, and all unsafe/FFI elsewhere is isolated and specifically verified/tested;
- OpenID and EUDI functional conformance gates pass for every advertised profile;
- cryptographic, PKI, WIA/KA, status, subject-proofing, and HSM policies are deployed and monitored;
- deletion/privacy obligations have executable evidence;
- residual risks and TCB assumptions are approved by the responsible security, compliance, and scheme authorities.

## 18. Decisions that must be recorded before implementation

The architecture can proceed with defaults, but production requires explicit records for:

1. issuer role: PID, QEAA, PuB-EAA, or non-qualified EAA;
2. exact credential type and rulebook version;
3. first credential format and mandatory second-format roadmap;
4. integrated versus external Authorization Server and trust boundary;
5. Wallet client-attestation, WIA/KA, registrar, and trust-list providers;
6. subject identity/evidence source and LoA mapping;
7. status/revocation mechanism and freshness service levels;
8. HSM topology, issuer key/certificate profile, and signing ceremony;
9. batch/reuse/refresh policy and privacy method;
10. deployment jurisdiction, legal category, conformity-assessment and audit plan.

These are profile inputs, not implementation details. Changing one requires impact analysis, requirement remapping, proof reruns, and conformance reruns.

## 19. Official references for the baseline

- [EUDI ARF 2.9.0](https://eudi.dev/2.9.0/)
- [ARF 2.9.0 Annex 2 high-level requirements](https://eudi.dev/2.9.0/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/)
- [OpenID for Verifiable Credential Issuance 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VC High Assurance Interoperability Profile 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [EC TS03 v1.5.2 publication record](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/issues/17)
- [EUDI Attestation Rulebooks Catalog](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog)
- [OpenID Foundation conformance suite](https://openid.net/certification/)
- [EUDI Functional Conformance](https://conformance.eudi.dev/)
- [Lean](https://lean-lang.org/)
- [Tamarin Prover](https://tamarin-prover.com/)
- [Aeneas Rust-to-Lean use case](https://lean-lang.org/use-cases/aeneas/)
