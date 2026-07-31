# Experimental hybrid post-quantum issuance

Status: development-only, non-EUDI, disabled by default.

Set `ENABLE_EXPERIMENTAL_HYBRID_PQ=true` to advertise and issue
`dev.advatar.hybrid-pq.sd-jwt.v1`. This switch does not change PID, QEAA,
TLSNotary, standard SD-JWT VC, mdoc, DPoP, metadata-signing, proof-signing, or
JWKS behavior. In particular, ML-DSA is not included in
`credential_signing_alg_values_supported`.

The private profile document is published at
`/experimental/hybrid-pq/profile`. It identifies the P-256 and ML-DSA-65
public keys, their shared logical generation, and the acceptance rule:

```text
ES256 valid AND ML-DSA-65 valid
```

The ML-DSA secret key is encrypted at rest with AES-256-GCM. Its wrapping key
is held as a macOS Keychain generic-password item. The ciphertext is stored
under `HYBRID_PQ_KEY_DIR`, or `.hybrid-pq` when that variable is unset. The
plaintext secret buffer exists only for a signing operation and is zeroized
before return. If the P-256 identity changes, a new ML-DSA key is generated and
the logical generation advances.

## Frozen TBS contract and provisional envelope

The issuer consumes the exact `HybridContextV1` and `HybridTBSV1` contract and
three TBS vectors merged by EUWallet PR #100. The purpose is
`test-sd-jwt-wrapper-v1`. Context bytes start with
`EUWALLET-HYBRID-CONTEXT-V1`; tagged fields use a one-byte tag followed by an
unsigned 32-bit big-endian length and value. The context binds wallet identity,
optional issuer identity, logical key generation, optional transaction/session
and audience values, a 16–64 byte nonce, creation and expiry times, and an
optional 32-byte transcript hash. Purpose-specific required and forbidden fields
fail closed.

The TBS is:

```text
"EUWALLET-HYBRID-SIGNATURE-V1"
|| u32be(length(profile)) || profile
|| u32be(length(purpose)) || purpose
|| u32be(length(context)) || context
|| u32be(length(payload)) || payload
```

Both ES256 and ML-DSA-65 sign these exact bytes. Rust tests and CI checksum
gates consume all three shared TBS vectors.

The current private envelope remains provisional pending the shared envelope,
public-key, signature, encoded-envelope, and adversarial vectors tracked by
EUWallet issue #83. It begins with the mandatory magic bytes
`EUWALLET-EXPERIMENTAL-HYBRID-PQ-V1\0`, followed by canonical CBOR integer map
labels:

| Label | Field | Type |
|---:|---|---|
| 1 | version | unsigned integer (`1`) |
| 2 | profile | text (`euwallet-hybrid-pq-v1`) |
| 3 | purpose | text (`test-sd-jwt-wrapper-v1`) |
| 4 | credential format | text (`dev-hybrid-pq+cbor`) |
| 5 | canonical credential payload | byte string |
| 6 | disclosures | array of byte strings |
| 7 | classical key ID | text |
| 8 | PQ key ID | text |
| 9 | logical key generation | unsigned integer |
| 10 | ES256 signature | 64-byte byte string |
| 11 | ML-DSA-65 signature | 3309-byte byte string |

The signed payload component is canonical CBOR containing labels `1`
(credential payload bytes) and `2` (disclosure byte strings), so disclosure
mutation is signed and fails closed.

The issuer and EUWallet must jointly pin this envelope by consuming the same
positive and mutation vectors before envelope interoperability is claimed. The
current formal and executable evidence is documented in
`docs/hybrid-pq-verification-report.md`.
