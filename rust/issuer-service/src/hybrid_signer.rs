//! macOS custody adapter for the experimental logical hybrid signing identity.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{TryRngCore, rngs::OsRng};
use security_framework::passwords::{get_generic_password, set_generic_password};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    hybrid_codec::{EnvelopeSignatures, UnsignedEnvelope, encode, tbs},
    pq_backend,
    signer::{KeychainSigner, SignerError},
};

const KEYCHAIN_SERVICE: &str = "dev.advatar.vcissuer.hybrid-pq";
const WRAPPING_ACCOUNT: &str = "aes-256-wrapping-key.v1";
const STORE_VERSION: u8 = 1;
const NONCE_BYTES: usize = 12;

#[derive(Debug, Error)]
pub enum HybridSignerError {
    #[error(transparent)]
    Classical(#[from] SignerError),
    #[error("hybrid key storage failed: {0}")]
    Storage(String),
    #[error("hybrid key wrapping failed")]
    Wrapping,
    #[error(transparent)]
    PostQuantum(#[from] pq_backend::PqBackendError),
    #[error("hybrid envelope construction failed")]
    Envelope,
}

pub struct HybridCredentialSigner {
    classical: KeychainSigner,
    pq_public_key: Vec<u8>,
    pq_kid: String,
    generation: u64,
    encrypted_key_path: PathBuf,
    wrapping_key: Zeroizing<Vec<u8>>,
}

impl HybridCredentialSigner {
    pub fn find_or_create(classical_label: &str) -> Result<Self, HybridSignerError> {
        let classical = KeychainSigner::find_or_create(classical_label)?;
        let encrypted_key_path = encrypted_key_path();
        let wrapping_key = load_or_create_wrapping_key(&encrypted_key_path)?;
        let stored = encrypted_key_path
            .exists()
            .then(|| load_stored_key(&encrypted_key_path, &wrapping_key))
            .transpose()?;
        let classical_kid_hash = Sha256::digest(classical.kid().as_bytes());
        let (generation, pq_public_key) = match stored {
            Some(stored) if stored.classical_kid_hash == classical_kid_hash.as_slice() => {
                (stored.generation, stored.public_key)
            }
            Some(stored) => {
                let generation = stored.generation.saturating_add(1);
                let generated = pq_backend::generate()?;
                persist_key(
                    &encrypted_key_path,
                    &wrapping_key,
                    generation,
                    &classical_kid_hash,
                    &generated.public_key,
                    &generated.secret_key,
                )?;
                (generation, generated.public_key)
            }
            None => {
                let generated = pq_backend::generate()?;
                persist_key(
                    &encrypted_key_path,
                    &wrapping_key,
                    1,
                    &classical_kid_hash,
                    &generated.public_key,
                    &generated.secret_key,
                )?;
                (1, generated.public_key)
            }
        };
        let pq_kid = URL_SAFE_NO_PAD.encode(Sha256::digest(&pq_public_key));
        Ok(Self {
            classical,
            pq_public_key,
            pq_kid,
            generation,
            encrypted_key_path,
            wrapping_key,
        })
    }

    pub fn classical_kid(&self) -> &str {
        self.classical.kid()
    }

    pub fn classical_public_key(&self) -> &[u8] {
        self.classical.public_key_bytes()
    }

    pub fn pq_kid(&self) -> &str {
        &self.pq_kid
    }

    pub fn pq_public_key(&self) -> &[u8] {
        &self.pq_public_key
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn sign_envelope(&self, unsigned: &UnsignedEnvelope) -> Result<Vec<u8>, HybridSignerError> {
        if unsigned.classical_kid != self.classical_kid()
            || unsigned.pq_kid != self.pq_kid
            || unsigned.generation != self.generation
        {
            return Err(HybridSignerError::Envelope);
        }
        let signed = tbs(unsigned).map_err(|_| HybridSignerError::Envelope)?;
        let classical = self.classical.sign_es256(&signed)?.to_vec();
        let stored = load_stored_key(&self.encrypted_key_path, &self.wrapping_key)?;
        if stored.generation != self.generation
            || stored.public_key != self.pq_public_key
            || stored.classical_kid_hash
                != Sha256::digest(self.classical.kid().as_bytes()).as_slice()
        {
            return Err(HybridSignerError::Storage(
                "logical key generation changed during signing".into(),
            ));
        }
        let post_quantum = pq_backend::sign_once(&stored.secret_key, &signed)?;
        encode(
            unsigned,
            &EnvelopeSignatures {
                classical,
                post_quantum,
            },
        )
        .map_err(|_| HybridSignerError::Envelope)
    }
}

struct StoredKey {
    generation: u64,
    classical_kid_hash: Vec<u8>,
    public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

fn encrypted_key_path() -> PathBuf {
    std::env::var_os("HYBRID_PQ_KEY_DIR")
        .map_or_else(|| PathBuf::from(".hybrid-pq"), PathBuf::from)
        .join("ml-dsa-65-key.v1")
}

fn load_or_create_wrapping_key(
    encrypted_key_path: &Path,
) -> Result<Zeroizing<Vec<u8>>, HybridSignerError> {
    match get_generic_password(KEYCHAIN_SERVICE, WRAPPING_ACCOUNT) {
        Ok(key) if key.len() == 32 => Ok(Zeroizing::new(key)),
        Ok(mut key) => {
            key.zeroize();
            Err(HybridSignerError::Storage(
                "Keychain wrapping key has an invalid length".into(),
            ))
        }
        Err(error) if encrypted_key_path.exists() => Err(HybridSignerError::Storage(format!(
            "Keychain wrapping key is unavailable for the existing PQ record: {error}"
        ))),
        Err(_) => {
            let mut key = Zeroizing::new(vec![0_u8; 32]);
            OsRng
                .try_fill_bytes(&mut key)
                .map_err(|_| HybridSignerError::Storage("system CSPRNG unavailable".into()))?;
            set_generic_password(KEYCHAIN_SERVICE, WRAPPING_ACCOUNT, &key)
                .map_err(|error| HybridSignerError::Storage(error.to_string()))?;
            Ok(key)
        }
    }
}

fn persist_key(
    path: &Path,
    wrapping_key: &[u8],
    generation: u64,
    classical_kid_hash: &[u8],
    public_key: &[u8],
    secret_key: &[u8],
) -> Result<(), HybridSignerError> {
    let cipher =
        Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| HybridSignerError::Wrapping)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| HybridSignerError::Storage("system CSPRNG unavailable".into()))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret_key)
        .map_err(|_| HybridSignerError::Wrapping)?;
    let mut encoded = Vec::with_capacity(
        1 + 8 + 32 + NONCE_BYTES + pq_backend::PUBLIC_KEY_BYTES + ciphertext.len(),
    );
    encoded.push(STORE_VERSION);
    encoded.extend_from_slice(&generation.to_be_bytes());
    encoded.extend_from_slice(classical_kid_hash);
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(public_key);
    encoded.extend_from_slice(&ciphertext);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| HybridSignerError::Storage(error.to_string()))?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| HybridSignerError::Storage(error.to_string()))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| HybridSignerError::Storage(error.to_string()))?;
    fs::rename(&temporary, path).map_err(|error| HybridSignerError::Storage(error.to_string()))
}

fn load_stored_key(path: &Path, wrapping_key: &[u8]) -> Result<StoredKey, HybridSignerError> {
    let encoded = fs::read(path).map_err(|error| HybridSignerError::Storage(error.to_string()))?;
    let header = 1 + 8 + 32 + NONCE_BYTES + pq_backend::PUBLIC_KEY_BYTES;
    if encoded.len() != header + pq_backend::SECRET_KEY_BYTES + 16
        || encoded.first().copied() != Some(STORE_VERSION)
    {
        return Err(HybridSignerError::Storage(
            "encrypted ML-DSA key record is malformed".into(),
        ));
    }
    let generation = u64::from_be_bytes(
        encoded[1..9]
            .try_into()
            .map_err(|_| HybridSignerError::Wrapping)?,
    );
    let classical_kid_hash = encoded[9..41].to_vec();
    let nonce = &encoded[41..41 + NONCE_BYTES];
    let public_start = 41 + NONCE_BYTES;
    let public_end = public_start + pq_backend::PUBLIC_KEY_BYTES;
    let public_key = encoded[public_start..public_end].to_vec();
    let cipher =
        Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| HybridSignerError::Wrapping)?;
    let secret_key = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(nonce), &encoded[public_end..])
            .map_err(|_| HybridSignerError::Wrapping)?,
    );
    if secret_key.len() != pq_backend::SECRET_KEY_BYTES {
        return Err(HybridSignerError::Storage(
            "decrypted ML-DSA key has an invalid length".into(),
        ));
    }
    Ok(StoredKey {
        generation,
        classical_kid_hash,
        public_key,
        secret_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_secret_is_encrypted_and_tampering_fails_closed() {
        let directory = tempfile::tempdir().expect("temporary key directory");
        let path = directory.path().join("pq-key");
        let wrapping_key = [9_u8; 32];
        let classical_hash = [4_u8; 32];
        let generated = pq_backend::generate().expect("system CSPRNG");
        persist_key(
            &path,
            &wrapping_key,
            7,
            &classical_hash,
            &generated.public_key,
            &generated.secret_key,
        )
        .expect("encrypted record");
        let encoded = fs::read(&path).expect("encrypted record bytes");
        assert!(
            !encoded
                .windows(generated.secret_key.len())
                .any(|window| window == generated.secret_key.as_slice())
        );
        let stored = load_stored_key(&path, &wrapping_key).expect("decrypt record");
        assert_eq!(stored.generation, 7);
        assert_eq!(stored.classical_kid_hash, classical_hash);
        assert_eq!(stored.public_key, generated.public_key);
        assert_eq!(
            stored.secret_key.as_slice(),
            generated.secret_key.as_slice()
        );

        let mut tampered = encoded;
        let last = tampered.last_mut().expect("record is nonempty");
        *last ^= 1;
        fs::write(&path, tampered).expect("tampered record");
        assert!(load_stored_key(&path, &wrapping_key).is_err());
    }
}
