//! Experimental ML-DSA-65 backend.
//!
//! Protocol code never calls `libcrux-ml-dsa` directly. Secret-key material is
//! accepted only for the duration of one operation and is cleared before return.

use libcrux_ml_dsa::ml_dsa_65::{
    MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey, generate_key_pair, sign, verify,
};
use rand::{TryRngCore, rngs::OsRng};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const PUBLIC_KEY_BYTES: usize = 1_952;
pub const SECRET_KEY_BYTES: usize = 4_032;
pub const SIGNATURE_BYTES: usize = 3_309;

#[derive(Debug, Error)]
pub enum PqBackendError {
    #[error("system CSPRNG is unavailable")]
    Random,
    #[error("ML-DSA-65 {component} has an invalid length")]
    InvalidLength { component: &'static str },
    #[error("ML-DSA-65 signing failed")]
    Signing,
    #[error("ML-DSA-65 verification failed")]
    Verification,
}

pub struct GeneratedKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

pub fn generate() -> Result<GeneratedKeyPair, PqBackendError> {
    let mut seed = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|_| PqBackendError::Random)?;
    let mut key_pair = generate_key_pair(seed);
    seed.zeroize();
    let public_key = key_pair.verification_key.as_slice().to_vec();
    let secret_key = Zeroizing::new(key_pair.signing_key.as_slice().to_vec());
    key_pair.signing_key.as_mut_slice().zeroize();
    Ok(GeneratedKeyPair {
        public_key,
        secret_key,
    })
}

pub fn sign_once(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, PqBackendError> {
    let encoded: [u8; SECRET_KEY_BYTES] =
        secret_key
            .try_into()
            .map_err(|_| PqBackendError::InvalidLength {
                component: "secret key",
            })?;
    let mut signing_key = MLDSA65SigningKey::new(encoded);
    let mut randomness = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut randomness)
        .map_err(|_| PqBackendError::Random)?;
    let result = sign(&signing_key, message, &[], randomness)
        .map(|signature| signature.as_slice().to_vec())
        .map_err(|_| PqBackendError::Signing);
    signing_key.as_mut_slice().zeroize();
    randomness.zeroize();
    result
}

pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PqBackendError> {
    let public_key = MLDSA65VerificationKey::new(public_key.try_into().map_err(|_| {
        PqBackendError::InvalidLength {
            component: "public key",
        }
    })?);
    let signature =
        MLDSA65Signature::new(
            signature
                .try_into()
                .map_err(|_| PqBackendError::InvalidLength {
                    component: "signature",
                })?,
        );
    verify(&public_key, message, &[], &signature).map_err(|_| PqBackendError::Verification)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_signs_and_verifies() {
        let key_pair = generate().expect("system CSPRNG");
        let signature = sign_once(&key_pair.secret_key, b"hybrid tbs").expect("signature");
        assert_eq!(key_pair.public_key.len(), PUBLIC_KEY_BYTES);
        assert_eq!(key_pair.secret_key.len(), SECRET_KEY_BYTES);
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        verify_signature(&key_pair.public_key, b"hybrid tbs", &signature).expect("verification");
        assert!(verify_signature(&key_pair.public_key, b"changed", &signature).is_err());
    }

    #[test]
    fn malformed_components_fail_before_backend_use() {
        assert!(sign_once(&[0_u8; 31], b"message").is_err());
        assert!(verify_signature(&[0_u8; 31], b"message", &[0_u8; SIGNATURE_BYTES]).is_err());
        assert!(verify_signature(&[0_u8; PUBLIC_KEY_BYTES], b"message", &[0_u8; 31]).is_err());
    }
}
