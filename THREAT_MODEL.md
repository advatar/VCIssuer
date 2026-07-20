# Threat Model

## Assets

- issuer signing keys and HSM authorization capabilities;
- authorization codes, access tokens, refresh tokens, DPoP keys/proofs, credential nonces, deferred transaction identifiers;
- Wallet Unit, WIA, KA, holder-key, and subject bindings;
- personal data, claim evidence, credentials, disclosures, salts, status indexes, and audit records;
- issuer metadata, access/registration certificates, trust anchors, and profile configuration;
- availability and integrity of status/revocation publication;
- proof and conformance evidence.

## Trust boundaries

1. Wallet Unit ↔ public issuer/authorization endpoints.
2. TLS termination/API gateway ↔ issuer runtime.
3. Runtime ↔ pure decision kernel.
4. Runtime ↔ database/queue/cache.
5. Runtime ↔ HSM/signing service.
6. Runtime ↔ trust lists, registrar, CA, WIA/KA and revocation sources.
7. Runtime ↔ subject identity/authentic sources.
8. Build system ↔ source/dependencies/toolchains/release registry.
9. Production telemetry ↔ operators/SIEM/support systems.

## Required threats and evidence

| ID | Threat | Required control/evidence |
|---|---|---|
| T-001 | Authorization code interception or mix-up | PAR, PKCE S256, exact redirect/client/issuer binding; Tamarin `FI-PROT-003`; negative tests. |
| T-002 | Stolen access token | DPoP sender constraint, nonce/replay handling; `FI-PROT-004`; replay tests. |
| T-003 | Credential proof replay | Single-use/fresh `c_nonce`, audience/time/key binding; Lean ledger invariant and `FI-PROT-005`. |
| T-004 | Cross-device QR/session swap | Bind offer/session/issuer/wallet/client and final holder key; `FI-PROT-009`; race tests. |
| T-005 | Issuance of unauthorized credential type or claims | Normalized authorization set, `MayIssue`, `FI-SAF-001/002`; fuzz authorization parsing. |
| T-006 | Fake or revoked Wallet Unit | WIA trust and status checks, freshness bounds; Tamarin revocation lemma; stale/failure tests. |
| T-007 | Holder key not in approved storage or no possession | KA/key storage validation and possession for all keys; `FI-SAF-005`; batch adversarial tests. |
| T-008 | Reissue to attacker wallet/key | Logical credential and same-wallet binding; `FI-SAF-010`, `FI-PROT-010`. |
| T-009 | Issuer not entitled to credential type | Access/registration certificate and registry/trust-list policy; metadata and pre-sign check. |
| T-010 | Parser differential/duplicate-key attack | Strict parsers, exact-byte verification, differential/fuzz/Kani tests. |
| T-011 | Algorithm/key confusion | Closed algorithm suite, protected header rules, key usage/EKU/policy checks; negative vectors. |
| T-012 | Certificate/path-building confusion | Profile-specific path validation and trust-anchor handling; adversarial chain corpus. |
| T-013 | Double issuance through retry/race | Revision/idempotency ledger, atomic capability consumption, exact digest reconciliation; concurrency model tests. |
| T-014 | Duplicate status index or predictable identifiers | Transactional reservation and CSPRNG/domain separation; uniqueness proof and load tests. |
| T-015 | Batch correlation | Independent fresh values, reduced timestamp precision, observational-equivalence model and traffic/log review. |
| T-016 | Linkability through retained WIA/KA/credential data | Typed retention transitions, no raw logs, deletion receipts, backup/queue coverage; `FI-SAF-011`. |
| T-017 | Deferred worker signs with stale evidence | Re-evaluate time-sensitive evidence immediately before sign; state-machine theorem and expiry tests. |
| T-018 | Refresh-token replay/theft | Rotation, reuse detection, DPoP/same-wallet binding, terminal compromise response. |
| T-019 | HSM signs outside verified path | Unforgeable single-use kernel capability, HSM API allow-list, audit reconciliation. |
| T-020 | Clock rollback/skew | Monotonic deadlines, wall-clock validation, fail-closed monitoring and simulation tests. |
| T-021 | Entropy failure/VM snapshot | DRBG health, fork reseed, domain separation, duplicate detection, incident policy. |
| T-022 | Malicious authentic source or identity operator | Signed provenance, independent policy checks, role separation, correction/revocation process; explicit assumption. |
| T-023 | Trust-list/registrar/status rollback | Signed version/freshness monotonicity, pinned roots, rollback protection, stale-data failure behavior. |
| T-024 | Build/dependency compromise | Hermetic builds, locked dependencies, provenance, SBOM, signature verification, reproducibility. |
| T-025 | Proof/configuration mismatch at deployment | Bind proof bundle to source/profile/config/binary digests and attest deployment. |
| T-026 | Denial of service through JSON/CBOR/certificate/path inputs | Strict size/depth/count limits, bounded work, rate limits, fuzz and load tests. |
| T-027 | Sensitive telemetry exfiltration | Compile-time redaction APIs, canary tests, telemetry schema review, egress controls. |
| T-028 | Insider key/config misuse | Quorum, separation of duties, signed promotions, HSM policy, immutable audit, alerting. |
| T-029 | Protocol downgrade/version confusion | Immutable profile IDs, no component mixing, explicit negotiation and conformance gate. |
| T-030 | Security proof omits corruption or real-world channel | Compromise lemmas, TCB/assumption review, empirical timing/network/log analysis. |

## Attacker classes

- unauthenticated remote network attacker;
- malicious or compromised wallet application/client;
- malicious user with a legitimate wallet;
- compromised Wallet Provider or Wallet Instance key;
- compromised issuer/authorization endpoint, database, operator, or CI account;
- malicious authentic source, registrar, trust-list/status source, CA, or HSM administrator;
- supply-chain attacker;
- passive cross-service correlation observer.

Each Tamarin theorem SHALL state which corruption events invalidate or weaken it. “Secure unless anything is compromised” is not an acceptable result; use minimal compromise/accountability sets.
