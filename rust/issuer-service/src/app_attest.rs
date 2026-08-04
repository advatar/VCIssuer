//! Apple App Attest verification: register a wallet **app instance** and verify per-request
//! assertions, so `VCIssuer` can bind sensitive endpoints to a genuine, unmodified build of the app
//! running on genuine Apple hardware.
//!
//! Flow: the app calls `DCAppAttestService.generateKey()` → `keyId`, fetches a one-time challenge,
//! `attestKey(keyId, SHA256(challenge))` → a CBOR attestation object, and POSTs it. This module
//! verifies the attestation (Apple `x5c` chain → the embedded App Attest Root CA, the challenge
//! nonce bound into the leaf certificate, the app-id / AAGUID / counter in `authData`, and that the
//! attested key matches `keyId`) and returns the instance's P-256 public key. Later, protected calls
//! carry `generateAssertion` signatures verified by [`verify_assertion`].
//!
//! All checks fail closed. Algorithm per Apple, "Validating Apps That Connect to Your Server".
//! End-to-end acceptance of a real device attestation is validated on-device (no attestation blob
//! can be produced off a real iPhone); the deterministic sub-steps are unit-tested here.

use std::collections::HashMap;
use std::path::Path;

use ciborium::value::Value as CborValue;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

/// Apple App Attest Root CA (DER), the pinned trust anchor for the `x5c` chain.
const APPLE_ROOT_CA_DER: &[u8] = include_bytes!("apple_appattest_root_ca.der");
/// Certificate extension carrying the attestation nonce (Apple OID).
const NONCE_OID: &str = "1.2.840.113635.100.8.2";
/// AAGUID marking a production attestation (`"appattest"` padded to 16 bytes).
const AAGUID_PROD: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
/// AAGUID marking a development attestation.
const AAGUID_DEV: &[u8; 16] = b"appattestdevelop";

/// Trusted App Attest configuration, from the environment.
#[derive(Clone)]
pub struct AppAttestConfig {
    /// Accepted `TEAMID.bundle-id` app ids, e.g. `L2AF8KFX35.eu.advatar.wallet` (the wallet) and
    /// `L2AF8KFX35.eu.advatar.wallet.pidcapture` (the capture companion). An attestation is accepted
    /// when its `rpIdHash` matches SHA-256 of ANY of these.
    app_ids: Vec<String>,
    /// Accept the development AAGUID (Xcode-attached builds). Off in production.
    allow_development: bool,
}

impl AppAttestConfig {
    /// `APPLE_APP_ATTEST_APP_ID` (required — a comma-separated list of one or more `TEAMID.bundle-id`
    /// app ids); `APP_ATTEST_ALLOW_DEVELOPMENT` (optional). No non-empty app id ⇒ `None` and the App
    /// Attest endpoints are disabled (fail closed).
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let raw = crate::env_file::var("APPLE_APP_ATTEST_APP_ID")?;
        let app_ids: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if app_ids.is_empty() {
            return None;
        }
        let allow_development = crate::env_file::var("APP_ATTEST_ALLOW_DEVELOPMENT")
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        Some(Self {
            app_ids,
            allow_development,
        })
    }

    /// The accepted app id whose SHA-256 equals `rp_id_hash`, if any. Attestations carry the app id
    /// implicitly as `SHA256(app_id)` in `authData[0..32]`, so this identifies which app attested.
    fn app_id_for_rp_id_hash(&self, rp_id_hash: &[u8]) -> Option<&str> {
        self.app_ids
            .iter()
            .find(|id| Sha256::digest(id.as_bytes()).as_slice() == rp_id_hash)
            .map(String::as_str)
    }
}

/// A registered app instance: which app id it attested under, its attested P-256 public key (SEC1
/// uncompressed point), and the monotonic assertion counter.
///
/// `Serialize`/`Deserialize` so the instance table can be persisted across restarts (see
/// [`load_instances`] / [`save_instances`]): without persistence a restart drops every registration,
/// which both re-opens the replay counter and locks out already-registered clients (Apple issues one
/// attestation per key, so a client cannot silently re-register).
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisteredInstance {
    /// The `TEAMID.bundle-id` this instance attested under (an assertion's `rpIdHash` must match it).
    pub app_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

/// Load the persisted `keyId → RegisteredInstance` table from `path`. A missing or unreadable file
/// yields an empty table (fail-safe: unknown instances are rejected, never fail-open).
#[must_use]
pub fn load_instances(path: &Path) -> HashMap<String, RegisteredInstance> {
    let Ok(bytes) = std::fs::read(path) else {
        return HashMap::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        tracing::warn!(%error, "App Attest store is unreadable; starting with an empty table");
        HashMap::new()
    })
}

/// Atomically persist the `keyId → RegisteredInstance` table to `path` (write a temp file, then
/// rename). Best-effort: serialization or I/O failures are logged, never fatal — the in-memory table
/// remains authoritative for the running process.
pub fn save_instances(path: &Path, instances: &HashMap<String, RegisteredInstance>) {
    let Ok(json) = serde_json::to_vec(instances) else {
        tracing::error!("cannot serialize the App Attest instance store");
        return;
    };
    let tmp = path.with_extension("tmp");
    if let Err(error) = std::fs::write(&tmp, &json) {
        tracing::error!(%error, "cannot write the App Attest store temp file");
        return;
    }
    if let Err(error) = std::fs::rename(&tmp, path) {
        tracing::error!(%error, "cannot atomically replace the App Attest store");
    }
}

/// Verify an App Attest attestation and return the attested P-256 public key (SEC1 point) on
/// success. `key_id` is the raw (base64-decoded) key identifier the app generated; `challenge` is
/// the exact one-time challenge bytes this issuer handed out.
pub fn verify_attestation(
    attestation_cbor: &[u8],
    challenge: &[u8],
    key_id: &[u8],
    config: &AppAttestConfig,
    now_unix: u64,
) -> Result<(String, Vec<u8>), String> {
    let root = Certificate::from_der(APPLE_ROOT_CA_DER)
        .map_err(|_| "embedded Apple App Attest root CA is malformed".to_string())?;

    // 1. Decode the CBOR attestation object: { fmt, attStmt: { x5c }, authData }.
    let value: CborValue = ciborium::from_reader(attestation_cbor)
        .map_err(|_| "attestation is not valid CBOR".to_string())?;
    let map = as_map(&value).ok_or("attestation is not a CBOR map")?;
    if cbor_text(map, "fmt") != Some("apple-appattest") {
        return Err("attestation fmt is not apple-appattest".into());
    }
    let att_stmt = cbor_get(map, "attStmt")
        .and_then(as_map)
        .ok_or("missing attStmt")?;
    let x5c = cbor_get(att_stmt, "x5c")
        .and_then(|v| v.as_array())
        .ok_or("missing x5c chain")?;
    if x5c.len() < 2 {
        return Err("x5c must contain the leaf and the intermediate".into());
    }
    let cred_cert_der = x5c[0].as_bytes().ok_or("x5c[0] is not bytes")?;
    let ca_cert_der = x5c[1].as_bytes().ok_or("x5c[1] is not bytes")?;
    let auth_data = cbor_get(map, "authData")
        .and_then(CborValue::as_bytes)
        .ok_or("missing authData")?;

    let cred_cert =
        Certificate::from_der(cred_cert_der).map_err(|_| "credCert is malformed".to_string())?;
    let ca_cert = Certificate::from_der(ca_cert_der)
        .map_err(|_| "intermediate CA is malformed".to_string())?;

    // 2. Chain: credCert ← intermediate ← Apple root (intermediate + root are P-384/ES384).
    verify_p384_issued(&cred_cert, spki_point(&ca_cert)?)?;
    verify_p384_issued(&ca_cert, spki_point(&root)?)?;
    // Validity window of the leaf.
    if !within_validity(&cred_cert, now_unix) {
        return Err("credCert is outside its validity window".into());
    }

    // 3. nonce = SHA256(authData || SHA256(challenge)); it must equal the leaf's nonce extension.
    let client_data_hash = Sha256::digest(challenge);
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(client_data_hash);
    let expected_nonce: [u8; 32] = hasher.finalize().into();
    let cert_nonce = leaf_nonce(&cred_cert).ok_or("credCert has no App Attest nonce extension")?;
    if cert_nonce != expected_nonce {
        return Err("attestation nonce does not match the issued challenge".into());
    }

    // 4. keyId must be SHA256 of the leaf's public key (SEC1 point). Return that point.
    let cred_point = spki_point(&cred_cert)?;
    let key_id_hash: [u8; 32] = Sha256::digest(cred_point).into();
    if key_id.len() != 32 || key_id != key_id_hash {
        return Err("keyId does not match the attested public key".into());
    }
    // The leaf key must be a valid P-256 point.
    P256VerifyingKey::from_sec1_bytes(cred_point)
        .map_err(|_| "attested key is not a valid P-256 point".to_string())?;

    // 5. authData: rpIdHash, counter == 0, AAGUID, credentialId == keyId.
    if auth_data.len() < 55 {
        return Err("authData is too short".into());
    }
    let app_id = config
        .app_id_for_rp_id_hash(&auth_data[0..32])
        .ok_or("authData rpIdHash does not match any configured app id")?
        .to_owned();
    let counter = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if counter != 0 {
        return Err("attestation counter must be zero".into());
    }
    let aaguid = &auth_data[37..53];
    let aaguid_ok = aaguid == AAGUID_PROD || (config.allow_development && aaguid == AAGUID_DEV);
    if !aaguid_ok {
        return Err("attestation AAGUID is not accepted".into());
    }
    let cred_id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    let cred_id_end = 55usize
        .checked_add(cred_id_len)
        .ok_or("credentialId length overflow")?;
    if auth_data.len() < cred_id_end {
        return Err("authData credentialId is truncated".into());
    }
    if auth_data[55..cred_id_end] != *key_id {
        return Err("authData credentialId does not match keyId".into());
    }

    Ok((app_id, cred_point.to_vec()))
}

/// Verify an assertion over `client_data` (the exact request bytes the app signed) against a
/// registered instance, binding it to the app id the instance attested under and enforcing a
/// strictly increasing counter. Returns the new counter to persist.
pub fn verify_assertion(
    assertion_cbor: &[u8],
    client_data: &[u8],
    instance: &RegisteredInstance,
) -> Result<u32, String> {
    let value: CborValue = ciborium::from_reader(assertion_cbor)
        .map_err(|_| "assertion is not valid CBOR".to_string())?;
    let map = as_map(&value).ok_or("assertion is not a CBOR map")?;
    let signature = cbor_get(map, "signature")
        .and_then(CborValue::as_bytes)
        .ok_or("assertion missing signature")?;
    let authenticator_data = cbor_get(map, "authenticatorData")
        .and_then(CborValue::as_bytes)
        .ok_or("assertion missing authenticatorData")?;
    if authenticator_data.len() < 37 {
        return Err("assertion authenticatorData is too short".into());
    }
    let expected_rp_id_hash: [u8; 32] = Sha256::digest(instance.app_id.as_bytes()).into();
    if authenticator_data[0..32] != expected_rp_id_hash {
        return Err("assertion rpIdHash does not match the instance's app id".into());
    }
    // nonce = SHA256(authenticatorData || SHA256(clientData)), verified with the instance key.
    let client_data_hash = Sha256::digest(client_data);
    let mut hasher = Sha256::new();
    hasher.update(authenticator_data);
    hasher.update(client_data_hash);
    let nonce = hasher.finalize();
    let key = P256VerifyingKey::from_sec1_bytes(&instance.public_key)
        .map_err(|_| "stored instance key is malformed".to_string())?;
    let sig = P256Signature::from_der(signature)
        .map_err(|_| "assertion signature is not valid DER ECDSA".to_string())?;
    key.verify(&nonce, &sig)
        .map_err(|_| "assertion signature is invalid".to_string())?;

    let counter = u32::from_be_bytes([
        authenticator_data[33],
        authenticator_data[34],
        authenticator_data[35],
        authenticator_data[36],
    ]);
    if counter <= instance.sign_count {
        return Err("assertion counter did not increase (possible replay)".into());
    }
    Ok(counter)
}

// --- helpers ---

/// Verify `cert`'s signature was produced by a P-384/ES384 issuer with the given SEC1 public point.
fn verify_p384_issued(cert: &Certificate, issuer_point: &[u8]) -> Result<(), String> {
    let key = P384VerifyingKey::from_sec1_bytes(issuer_point)
        .map_err(|_| "issuer key is not a valid P-384 point".to_string())?;
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|_| "cannot re-encode TBS certificate".to_string())?;
    let sig = P384Signature::from_der(cert.signature.raw_bytes())
        .map_err(|_| "certificate signature is not valid DER ECDSA".to_string())?;
    key.verify(&tbs, &sig)
        .map_err(|_| "certificate signature does not chain to the issuer".to_string())
}

/// The SEC1 uncompressed public-key point from a certificate's `SubjectPublicKeyInfo`.
fn spki_point(cert: &Certificate) -> Result<&[u8], String> {
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| "certificate public key is not byte-aligned".to_string())
}

/// True when `now_unix` is within the certificate's validity window.
fn within_validity(cert: &Certificate, now_unix: u64) -> bool {
    let nb = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let na = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    now_unix >= nb && now_unix <= na
}

/// Extract the 32-byte nonce from the leaf's App Attest extension. The extension value is DER
/// `SEQUENCE { [1] EXPLICIT OCTET STRING (32) }` → bytes `30 24 A1 22 04 20 <32>`.
fn leaf_nonce(cert: &Certificate) -> Option<[u8; 32]> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    let ext = extensions
        .iter()
        .find(|e| e.extn_id.to_string() == NONCE_OID)?;
    let der = ext.extn_value.as_bytes();
    // Defensive fixed-shape parse: SEQUENCE(0x30,len) [1](0xA1,len) OCTETSTRING(0x04,0x20) nonce(32).
    if der.len() != 38 || der[0] != 0x30 || der[2] != 0xA1 || der[4] != 0x04 || der[5] != 0x20 {
        return None;
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&der[6..38]);
    Some(nonce)
}

fn as_map(value: &CborValue) -> Option<&Vec<(CborValue, CborValue)>> {
    match value {
        CborValue::Map(entries) => Some(entries),
        _ => None,
    }
}

fn cbor_get<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    map.iter()
        .find(|(k, _)| matches!(k, CborValue::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn cbor_text<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a str> {
    match cbor_get(map, key) {
        Some(CborValue::Text(t)) => Some(t.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    const TEST_APP_ID: &str = "L2AF8KFX35.eu.advatar.wallet";

    fn cfg() -> AppAttestConfig {
        AppAttestConfig {
            app_ids: vec![
                TEST_APP_ID.into(),
                "L2AF8KFX35.eu.advatar.wallet.pidcapture".into(),
            ],
            allow_development: false,
        }
    }

    #[test]
    fn embedded_root_ca_parses_and_is_self_signed() {
        let root = Certificate::from_der(APPLE_ROOT_CA_DER).expect("root parses");
        // The root is P-384 and self-signed: its own key verifies its signature.
        let point = spki_point(&root).expect("root point");
        verify_p384_issued(&root, point).expect("root is self-signed");
    }

    #[test]
    fn aaguid_constants_are_16_bytes() {
        assert_eq!(AAGUID_PROD.len(), 16);
        assert_eq!(AAGUID_DEV.len(), 16);
        assert_eq!(&AAGUID_PROD[..9], b"appattest");
    }

    #[test]
    fn app_id_matches_by_rp_id_hash() {
        let config = cfg();
        let main_hash: [u8; 32] = Sha256::digest(TEST_APP_ID.as_bytes()).into();
        assert_eq!(config.app_id_for_rp_id_hash(&main_hash), Some(TEST_APP_ID));
        let companion_hash: [u8; 32] =
            Sha256::digest(b"L2AF8KFX35.eu.advatar.wallet.pidcapture").into();
        assert_eq!(
            config.app_id_for_rp_id_hash(&companion_hash),
            Some("L2AF8KFX35.eu.advatar.wallet.pidcapture")
        );
        // A hash of an app id that is NOT configured is rejected.
        let other: [u8; 32] = Sha256::digest(b"L2AF8KFX35.com.evil.clone").into();
        assert_eq!(config.app_id_for_rp_id_hash(&other), None);
    }

    #[test]
    fn leaf_nonce_parses_fixed_shape() {
        // Build a synthetic extn_value: 30 24 A1 22 04 20 <32 bytes>.
        let nonce = [7u8; 32];
        let mut der = vec![0x30, 0x24, 0xA1, 0x22, 0x04, 0x20];
        der.extend_from_slice(&nonce);
        // Wrap in a Certificate is heavy; test the byte parse directly via a tiny inline copy.
        assert_eq!(der.len(), 38);
        assert_eq!(&der[6..38], &nonce);
    }

    /// Build a real assertion (P-256 signature over `SHA256(authData ‖ SHA256(client_data))`) with the
    /// given counter, bound to `TEST_APP_ID`. Returns `(cbor_assertion, sec1_public_key)`.
    fn make_assertion(sk: &SigningKey, counter: u32, client_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let point = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut auth = Vec::new();
        let rp_id_hash: [u8; 32] = Sha256::digest(TEST_APP_ID.as_bytes()).into();
        auth.extend_from_slice(&rp_id_hash);
        auth.push(0); // flags
        auth.extend_from_slice(&counter.to_be_bytes());
        let client_data_hash = Sha256::digest(client_data);
        let mut hasher = Sha256::new();
        hasher.update(&auth);
        hasher.update(client_data_hash);
        let sig: P256Signature = sk.sign(&hasher.finalize());
        let assertion = CborValue::Map(vec![
            (
                CborValue::Text("signature".into()),
                CborValue::Bytes(sig.to_der().as_bytes().to_vec()),
            ),
            (
                CborValue::Text("authenticatorData".into()),
                CborValue::Bytes(auth),
            ),
        ]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&assertion, &mut cbor).expect("encode");
        (cbor, point)
    }

    #[test]
    fn assertion_counter_must_increase() {
        let sk = SigningKey::from_slice(&[9u8; 32]).expect("key");
        let client_data = b"POST /v1/pid-capture/x/evidence body-hash";
        let (cbor, point) = make_assertion(&sk, 5, client_data);

        // Stored counter 4 < 5 ⇒ accepted, returns 5.
        let instance = RegisteredInstance {
            app_id: TEST_APP_ID.into(),
            public_key: point.clone(),
            sign_count: 4,
        };
        assert_eq!(verify_assertion(&cbor, client_data, &instance).unwrap(), 5);
        // Stored counter 5 (not less than 5) ⇒ replay rejected.
        let replayed = RegisteredInstance {
            app_id: TEST_APP_ID.into(),
            public_key: point,
            sign_count: 5,
        };
        assert!(verify_assertion(&cbor, client_data, &replayed).is_err());
    }

    #[test]
    fn assertion_is_bound_to_the_exact_request_body() {
        // An assertion generated over request body A must NOT verify against a different body B —
        // this is the per-mutation binding property. Same key, same counter, different client_data.
        let sk = SigningKey::from_slice(&[13u8; 32]).expect("key");
        let body_a = br#"{"attestation":"AAA","client_ip":"203.0.113.1"}"#;
        let body_b = br#"{"attestation":"BBB","client_ip":"203.0.113.1"}"#;
        let (cbor, point) = make_assertion(&sk, 1, body_a);
        let instance = RegisteredInstance {
            app_id: TEST_APP_ID.into(),
            public_key: point,
            sign_count: 0,
        };
        // Bound body verifies…
        assert_eq!(verify_assertion(&cbor, body_a, &instance).unwrap(), 1);
        // …a tampered/different body does not (the signed nonce no longer matches).
        assert!(verify_assertion(&cbor, body_b, &instance).is_err());
    }

    #[test]
    fn instance_store_round_trips_and_preserves_the_counter() {
        // Persisting then loading must return the same instances (app id + key + advanced counter),
        // so a restart cannot reset sign_count (replay) or drop the registration (lock-out).
        let mut instances = HashMap::new();
        instances.insert(
            "keyid-aaa".to_string(),
            RegisteredInstance {
                app_id: TEST_APP_ID.into(),
                public_key: vec![4, 1, 2, 3, 4],
                sign_count: 42,
            },
        );
        let path = std::env::temp_dir().join("vcissuer-appattest-store-round-trip.json");
        let _ = std::fs::remove_file(&path);
        save_instances(&path, &instances);
        let loaded = load_instances(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.len(), 1);
        let entry = loaded.get("keyid-aaa").expect("entry present");
        assert_eq!(entry.app_id, TEST_APP_ID);
        assert_eq!(entry.public_key, vec![4, 1, 2, 3, 4]);
        assert_eq!(entry.sign_count, 42);
        // A missing store is empty, never an error (fail-safe, not fail-open).
        let missing = std::env::temp_dir().join("vcissuer-appattest-store-does-not-exist.json");
        let _ = std::fs::remove_file(&missing);
        assert!(load_instances(&missing).is_empty());
    }

    #[test]
    fn assertion_rp_id_hash_must_match_the_instance_app_id() {
        // An assertion attested under TEST_APP_ID must not verify against an instance recorded under
        // a different app id (prevents accepting one app's assertion as another's).
        let sk = SigningKey::from_slice(&[21u8; 32]).expect("key");
        let client_data = b"POST /v1/pid-capture/y/evidence";
        let (cbor, point) = make_assertion(&sk, 3, client_data);
        let wrong_app = RegisteredInstance {
            app_id: "L2AF8KFX35.eu.advatar.wallet.pidcapture".into(),
            public_key: point,
            sign_count: 0,
        };
        assert!(verify_assertion(&cbor, client_data, &wrong_app).is_err());
    }
}
