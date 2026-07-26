//! macOS Keychain-backed development signing adapter.
//!
//! Private key operations remain inside Security.framework. This module is an
//! effectful trusted-computing-base adapter and is intentionally kept outside
//! the pure issuer kernel.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::Signature;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, Ia5String, IsCa, KeyPair, KeyUsagePurpose,
    RemoteKeyPair, SanType, SerialNumber, SignatureAlgorithm,
};
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
    #[error("development certificate generation failed: {0}")]
    Certificate(String),
}

pub struct KeychainSigner {
    key: SecKey,
    kid: String,
    x: String,
    y: String,
    public_key: Vec<u8>,
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
        Ok(Self {
            key,
            kid,
            x,
            y,
            public_key: encoded,
        })
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
        let der = self.sign_der(message)?;
        let signature = Signature::from_der(&der).map_err(|_| SignerError::InvalidSignature)?;
        Ok(signature.to_bytes().into())
    }

    pub fn development_certificate_der(label: &str) -> Result<Vec<u8>, SignerError> {
        let signer = Self::find_or_create(label)?;
        let remote = KeychainRemote {
            public_key: signer.public_key.clone(),
            signer,
        };
        let key_pair = KeyPair::from_remote(Box::new(remote))
            .map_err(|error| SignerError::Certificate(error.to_string()))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| SignerError::Certificate(error.to_string()))?;
        params
            .distinguished_name
            .push(DnType::CommonName, format!("{label} development signer"));
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.serial_number = Some(SerialNumber::from_slice(
            &Sha256::digest(label.as_bytes())[..16],
        ));
        params
            .self_signed(&key_pair)
            .map(|certificate| certificate.der().to_vec())
            .map_err(|error| SignerError::Certificate(error.to_string()))
    }

    pub fn development_certificate_chain(
        ca_label: &str,
        leaf_label: &str,
        issuer_uri: &str,
    ) -> Result<Vec<Vec<u8>>, SignerError> {
        let ca_signer = Self::find_or_create(ca_label)?;
        let ca_key_pair = KeyPair::from_remote(Box::new(KeychainRemote {
            public_key: ca_signer.public_key.clone(),
            signer: ca_signer,
        }))
        .map_err(|error| SignerError::Certificate(error.to_string()))?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| SignerError::Certificate(error.to_string()))?;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Advatar development attestation CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.serial_number = Some(SerialNumber::from_slice(
            &Sha256::digest(ca_label.as_bytes())[..16],
        ));
        let ca = ca_params
            .self_signed(&ca_key_pair)
            .map_err(|error| SignerError::Certificate(error.to_string()))?;

        let leaf_signer = Self::find_or_create(leaf_label)?;
        let leaf_key_pair = KeyPair::from_remote(Box::new(KeychainRemote {
            public_key: leaf_signer.public_key.clone(),
            signer: leaf_signer,
        }))
        .map_err(|error| SignerError::Certificate(error.to_string()))?;
        let mut leaf_params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| SignerError::Certificate(error.to_string()))?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "TLSNotary evidence development signer");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(issuer_uri)
                .map_err(|error| SignerError::Certificate(error.to_string()))?,
        )];
        leaf_params.serial_number = Some(SerialNumber::from_slice(
            &Sha256::digest(format!("{leaf_label}:{issuer_uri}").as_bytes())[..16],
        ));
        let leaf = leaf_params
            .signed_by(&leaf_key_pair, &ca, &ca_key_pair)
            .map_err(|error| SignerError::Certificate(error.to_string()))?;
        Ok(vec![leaf.der().to_vec(), ca.der().to_vec()])
    }

    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|error| SignerError::Keychain(error.to_string()))
    }
}

struct KeychainRemote {
    signer: KeychainSigner,
    public_key: Vec<u8>,
}

impl RemoteKeyPair for KeychainRemote {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.signer
            .sign_der(message)
            .map_err(|_| rcgen::Error::RingUnspecified)
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
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

    #[test]
    #[ignore = "creates and accesses persistent macOS Keychain keys"]
    fn creates_a_distinct_development_leaf_and_ca() {
        let chain = KeychainSigner::development_certificate_chain(
            "dev.advatar.vcissuer.test-ca",
            "dev.advatar.vcissuer.test-leaf",
            "https://issuer.example",
        )
        .expect("certificate chain");
        assert_eq!(chain.len(), 2);
        assert!(!chain[0].is_empty());
        assert!(!chain[1].is_empty());
        assert_ne!(chain[0], chain[1]);
    }
}
