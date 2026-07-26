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
- [ ] Merge, verify `origin/main`, and delete the branch.
