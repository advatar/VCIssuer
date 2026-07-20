//! macOS Keychain-backed development signing adapter.
//!
//! Private key operations remain inside Security.framework. This module is an
//! effectful trusted-computing-base adapter and is intentionally kept outside
//! the pure issuer kernel.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::Signature;
use security_framework::{
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("macOS Keychain operation failed: {0}")]
    Keychain(String),
    #[error(
        "Keychain public key has an unexpected encoding (length={length}, prefix={prefix:#04x})"
    )]
    InvalidPublicKey { length: usize, prefix: u8 },
    #[error("Keychain returned an invalid ECDSA signature")]
    InvalidSignature,
}

pub struct KeychainSigner {
    key: SecKey,
    kid: String,
    x: String,
    y: String,
}

impl KeychainSigner {
    pub fn find_or_create(label: &str) -> Result<Self, SignerError> {
        if let Some(key) = find_private_key(label)? {
            match Self::from_key(key) {
                Ok(signer) => return Ok(signer),
                Err(SignerError::InvalidPublicKey { .. }) => {
                    let stale = find_private_key(label)?.ok_or_else(|| {
                        SignerError::Keychain("invalid key disappeared during replacement".into())
                    })?;
                    stale
                        .delete()
                        .map_err(|error| SignerError::Keychain(error.to_string()))?;
                }
                Err(error) => return Err(error),
            }
        }
        create_key(label)?;
        let key = find_private_key(label)?.ok_or_else(|| {
            SignerError::Keychain("generated key was not found in the Keychain".into())
        })?;
        Self::from_key(key)
    }

    fn from_key(key: SecKey) -> Result<Self, SignerError> {
        let encoded = key
            .public_key()
            .and_then(|public| public.external_representation())
            .map(|data| data.to_vec())
            .ok_or(SignerError::InvalidPublicKey {
                length: 0,
                prefix: 0,
            })?;
        if encoded.len() != 65 || encoded[0] != 0x04 {
            return Err(SignerError::InvalidPublicKey {
                length: encoded.len(),
                prefix: encoded.first().copied().unwrap_or_default(),
            });
        }
        let x = URL_SAFE_NO_PAD.encode(&encoded[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&encoded[33..65]);
        let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        Ok(Self { key, kid, x, y })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn public_jwk(&self) -> Value {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": self.x,
            "y": self.y,
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid
        })
    }

    pub fn sign_es256(&self, message: &[u8]) -> Result<[u8; 64], SignerError> {
        let der = self
            .key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|error| SignerError::Keychain(error.to_string()))?;
        let signature = Signature::from_der(&der).map_err(|_| SignerError::InvalidSignature)?;
        Ok(signature.to_bytes().into())
    }
}

fn create_key(label: &str) -> Result<(), SignerError> {
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_label(label)
        .set_location(Location::DefaultFileKeychain);
    SecKey::new(&options)
        .map(|_| ())
        .map_err(|error| SignerError::Keychain(error.to_string()))
}

fn find_private_key(label: &str) -> Result<Option<SecKey>, SignerError> {
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .limit(1)
        .search();
    match results {
        Ok(results) => Ok(results.into_iter().find_map(|result| match result {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        })),
        Err(error) if error.code() == -25300 => Ok(None),
        Err(error) => Err(SignerError::Keychain(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    #[test]
    #[ignore = "creates and accesses a persistent macOS Keychain key"]
    fn signs_with_keychain_key() {
        let signer = KeychainSigner::find_or_create("dev.advatar.vcissuer.test")
            .expect("test key must be available");
        let signature = signer.sign_es256(b"test message").expect("must sign");
        let jwk = signer.public_jwk();
        let x = URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().expect("x"))
            .expect("x base64url");
        let y = URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().expect("y"))
            .expect("y base64url");
        let point = p256::EncodedPoint::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );
        let key = VerifyingKey::from_encoded_point(&point).expect("public key");
        key.verify(
            b"test message",
            &Signature::from_slice(&signature).expect("raw signature"),
        )
        .expect("signature verifies");
    }
}
