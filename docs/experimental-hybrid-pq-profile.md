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

## Provisional envelope checkpoint

The current codec is intentionally private and provisional pending the shared
EUWallet vectors. It uses canonical CBOR integer map labels:

| Label | Field | Type |
|---:|---|---|
| 1 | version | unsigned integer (`1`) |
| 2 | profile | text (`euwallet-hybrid-pq-v1`) |
| 3 | purpose | text (`experimental-sd-jwt-wrapper`) |
| 4 | credential format | text (`dev-hybrid-pq+cbor`) |
| 5 | canonical credential payload | byte string |
| 6 | disclosures | array of byte strings |
| 7 | classical key ID | text |
| 8 | PQ key ID | text |
| 9 | logical key generation | unsigned integer |
| 10 | ES256 signature | 64-byte byte string |
| 11 | ML-DSA-65 signature | 3309-byte byte string |

TBS lengths are unsigned 32-bit big-endian integers. The `payload` TBS
component is canonical CBOR containing labels `1` (credential payload bytes)
and `2` (disclosure byte strings), so disclosure mutation is signed and fails
closed. The context is canonical CBOR binding issuer, audience, nonce, holder
key thumbprint, logical generation, and issue time.

The issuer and EUWallet must replace or formally pin this checkpoint by
consuming the same shared positive and mutation vectors before interoperability
is claimed.
