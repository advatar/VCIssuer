# Status

## Restore issuer TLS service

- [x] Create operations issue: https://github.com/advatar/VCIssuer/issues/19
- [x] Identify the port-443 proxy conflict and preserve the existing SNI routes.
- [x] Restore a valid TLS certificate and route issuer traffic to the Keychain signer.
- [x] Verify signed issuer metadata and the expected five-key JWKS over public HTTPS.
- [x] Make the deployed smoke probe blocking again.
- [x] Merge, verify `origin/main`, close the issue, and delete the branch.

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
- [ ] Complete live profile publication and deployment follow-up:
      https://github.com/advatar/VCIssuer/issues/23
  - [x] Publish the jointly frozen wrapper and completed shared-corpus status from the profile endpoint.
  - [x] Add regression tests and pass the full issuer verification gates.
  - [x] Enable the isolated experimental profile on the development deployment and verify live
        metadata, profile, offer creation, and standard-profile isolation.
  - [x] Merge to `main`, verify reachability, close #23, and delete the issue branch.
- [x] Pin the high-level experimental profile to `euwallet-hybrid-pq-v1`, ES256 AND
  ML-DSA-65, and configuration `dev.advatar.hybrid-pq.sd-jwt.v1`.
- [x] Jointly freeze with EUWallet the credential-wrapper canonical-CBOR schema and shared
  payload/disclosure/context plus real-key/signature adversarial corpus; the provisional issuer
  wrapper is pinned as `HybridCredentialWrapperV1` by EUWallet issue #119 (backend and
  atomic wallet sign/verify prerequisites #85, #87, #88, and use-case isolation #90 are complete).
- [x] Complete the initial ML-DSA dependency review, key-custody design, SBOM delta, and
  evidence record; retain external audit, KAT, and shared-vector gates.
- [x] Add disabled-by-default experimental issuance without changing certified EUDI paths.
- [x] Require atomic classical and post-quantum protection with downgrade rejection.
- [x] Add local adversarial, isolation, and regression tests.
- [x] Align `HybridContextV1` and `HybridTBSV1` with the contract and three TBS vectors merged by
  EUWallet PR #100.
- [x] Consume the standalone public-key and dual-signature envelope schema frozen by EUWallet
  PR #103, without misrepresenting it as the still-unfrozen credential wrapper.
- [x] Publish and consume one deterministic cross-repository component corpus containing a real
  ES256 key/signature, ML-DSA-65 key/signature, canonical TBS, both frozen component envelopes,
  and structural rejection mutations (merged via VCIssuer PR #20 and EUWallet PR #107).
- [x] Extend Lean with machine-checked hybrid AND-acceptance, same-TBS, generation-binding, and
  downgrade-rejection theorems, with zero `sorry` placeholders.
- [x] Extend Tamarin with atomic hybrid issuance, same-message agreement, component-removal
  downgrade rejection, and logical-generation agreement lemmas.
- [x] Add a reproducible formal-evidence report and publish its precisely scoped results on the
  issuer landing page.
- [x] Merge the initial implementation and verify it is reachable from `origin/main`.
- [x] Pin and consume the complete shared credential-wrapper/signature vectors in both repositories
  (`hybrid-pq-v1-wrapper-envelope.hex` plus twenty-one rejection mutations, byte-identical with
  EUWallet), merge the final interoperability update, and delete the issue branch.
- [x] Promote the live experimental hybrid-PQ profile above the fold on the landing page, retain
  its explicit non-EUDI scope, and publish the issuer JWKS link (just-issuer issue #9).
- [ ] [#26](https://github.com/advatar/VCIssuer/issues/26): make the jointly frozen wrapper
      consumable by the real wallet acquisition verifier.
  - [x] Replace the placeholder corpus payload with the canonical structured credential payload.
  - [x] Bind the holder JWK thumbprint to the signed wallet identity and retain all mutations.
  - [ ] Re-pin both repositories, pass issuer/wallet gates, merge, and verify `origin/main`.
