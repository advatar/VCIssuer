# Status

## PID-bound education credentials

- [x] Create issuer issue: https://github.com/advatar/VCIssuer/issues/2
- [x] Create wallet interoperability issue: https://github.com/advatar/EUWallet/issues/28
- [x] Publish distinct bound and independently identified education configurations.
- [x] Verify PID VP issuer signature, disclosures, validity, subject match and PID-key binding proof.
- [x] Bind the signing kernel to verified cross-attestation evidence and reject replay/mismatch.
- [x] Add EUWallet metadata, signing-input, request-assembly and response-validation support.
- [x] Add focused issuer and wallet tests and run clippy.

## TLSNotary evidence issuance

- [x] Create issuer issue: https://github.com/advatar/VCIssuer/issues/3
- [x] Define and verify the bounded `tlsn.notary-artifact.v1` contract with a pinned notary key.
- [x] Reject stale, future, replayed, malformed, wrongly signed, and oversized evidence.
- [x] Publish a development-only TLS evidence credential configuration without PID/(Q)EAA promotion.
- [x] Bind verified evidence to a short-lived authorization-code offer and the issued credential.
- [x] Return an EUWallet-compatible by-reference credential-offer deep link.
- [x] Add adversarial and successful endpoint/issuance tests, document configuration, and pass clippy.
- [x] Commit, push, merge to `main`, and verify the implementation is reachable from `origin/main`.

## Final OID4VCI credential-proof request interoperability

- [x] Create issuer issue: https://github.com/advatar/VCIssuer/issues/5
- [x] Accept exactly one JWT proof from the final `proofs.jwt` array request shape.
- [x] Reject missing, empty, multiple, unknown, and legacy ambiguous proof shapes.
- [x] Preserve nonce, audience, holder-key, and DPoP binding validation.
- [x] Add successful and adversarial endpoint tests and pass formatting, tests, and clippy.
- [x] Commit, push, merge to `main`, and delete the implementation branch.

## Wallet-compatible credential nonce encoding

- [x] Create issuer issue: https://github.com/advatar/VCIssuer/issues/7
- [x] Emit a cryptographically random non-zero `u64` as canonical decimal `c_nonce` text.
- [x] Preserve exact nonce proof binding and one-use replay rejection.
- [x] Add focused tests and pass formatting, tests, and clippy.
- [x] Merge to `main`, verify reachability, and delete the branch.

## Development credential-signing certificate path

- [x] Create issuer issue: https://github.com/advatar/VCIssuer/issues/9
- [x] Create a development attestation CA and exact-issuer TLSNotary signing leaf.
- [x] Publish and advertise the bounded leaf/root path without reusing the HTTPS identity.
- [x] Test key/profile binding and pass tests/clippy.
- [x] Merge, verify `origin/main`, and delete the branch.

## Mandatory PAR discovery metadata

- [x] Create issuer issue: https://github.com/advatar/VCIssuer/issues/11
- [x] Advertise the PAR requirement in authorization-server metadata.
- [x] Add a regression test and pass tests/clippy.
- [x] Merge, verify `origin/main`, and delete the branch.

## Experimental hybrid post-quantum issuance

- [x] Create issuer issue: https://github.com/advatar/VCIssuer/issues/13
- [x] Pin the high-level experimental profile to `euwallet-hybrid-pq-v1`, ES256 AND
  ML-DSA-65, and configuration `dev.advatar.hybrid-pq.sd-jwt.v1`.
- [ ] Jointly freeze with EUWallet the credential-wrapper canonical-CBOR schema and shared
  payload/disclosure/context plus real-key/signature adversarial corpus; replace or pin the
  provisional issuer wrapper before claiming interoperability (EUWallet #90 and #91; backend and
  atomic wallet sign/verify prerequisites #85, #87, and #88 are complete).
- [x] Complete the initial ML-DSA dependency review, key-custody design, SBOM delta, and
  evidence record; retain external audit, KAT, and shared-vector gates.
- [x] Add disabled-by-default experimental issuance without changing certified EUDI paths.
- [x] Require atomic classical and post-quantum protection with downgrade rejection.
- [x] Add local adversarial, isolation, and regression tests.
- [x] Align `HybridContextV1` and `HybridTBSV1` with the contract and three TBS vectors merged by
  EUWallet PR #100.
- [x] Consume the standalone public-key and dual-signature envelope schema frozen by EUWallet
  PR #103, without misrepresenting it as the still-unfrozen credential wrapper.
- [ ] Publish and consume one deterministic cross-repository component corpus containing a real
  ES256 key/signature, ML-DSA-65 key/signature, canonical TBS, both frozen component envelopes,
  and structural rejection mutations; retain the larger credential-wrapper corpus gate.
- [x] Extend Lean with machine-checked hybrid AND-acceptance, same-TBS, generation-binding, and
  downgrade-rejection theorems, with zero `sorry` placeholders.
- [x] Extend Tamarin with atomic hybrid issuance, same-message agreement, component-removal
  downgrade rejection, and logical-generation agreement lemmas.
- [x] Add a reproducible formal-evidence report and publish its precisely scoped results on the
  issuer landing page.
- [x] Merge the initial implementation and verify it is reachable from `origin/main`.
- [ ] Pin and consume the complete shared credential-wrapper/signature vectors in both repositories,
  merge the final interoperability update, and delete the issue branch.
