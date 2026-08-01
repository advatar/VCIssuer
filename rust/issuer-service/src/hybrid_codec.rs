//! Private `euwallet-hybrid-pq-v1` envelope, jointly frozen with `EUWallet`.
//!
//! The credential wrapper implements `HybridCredentialWrapperV1` (EUWallet
//! issue #119); the component containers implement the EUWallet PR #103
//! schema. Both are pinned by shared cross-repository vectors.

use std::{collections::BTreeSet, io::Cursor};

use ciborium::value::{Integer, Value};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use thiserror::Error;

use crate::pq_backend;

pub const VERSION: u64 = 1;
pub const PROFILE: &str = "euwallet-hybrid-pq-v1";
pub const PURPOSE: &str = "test-sd-jwt-wrapper-v1";
pub const FORMAT: &str = "dev-hybrid-pq+cbor";
const DOMAIN: &[u8] = b"EUWALLET-HYBRID-SIGNATURE-V1";
const CONTEXT_DOMAIN: &[u8] = b"EUWALLET-HYBRID-CONTEXT-V1";
const ENVELOPE_MAGIC: &[u8] = b"EUWALLET-EXPERIMENTAL-HYBRID-PQ-V1\0";
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_COMPONENT_ENVELOPE_BYTES: usize = 8 * 1024;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_KEY_ID_BYTES: usize = 128;
const MIN_NONCE_BYTES: usize = 16;
const MAX_NONCE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HybridPurpose {
    WalletExportV1,
    WalletRecoveryV1,
    PrivateProviderMessageV1,
    TestSdJwtWrapperV1,
    TestMdocWrapperV1,
}

impl HybridPurpose {
    pub const fn id(self) -> &'static str {
        match self {
            Self::WalletExportV1 => "wallet-export-v1",
            Self::WalletRecoveryV1 => "wallet-recovery-v1",
            Self::PrivateProviderMessageV1 => "private-provider-message-v1",
            Self::TestSdJwtWrapperV1 => PURPOSE,
            Self::TestMdocWrapperV1 => "test-mdoc-wrapper-v1",
        }
    }
}

impl TryFrom<&str> for HybridPurpose {
    type Error = HybridCodecError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "wallet-export-v1" => Ok(Self::WalletExportV1),
            "wallet-recovery-v1" => Ok(Self::WalletRecoveryV1),
            "private-provider-message-v1" => Ok(Self::PrivateProviderMessageV1),
            PURPOSE => Ok(Self::TestSdJwtWrapperV1),
            "test-mdoc-wrapper-v1" => Ok(Self::TestMdocWrapperV1),
            _ => Err(HybridCodecError::Unsupported),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridContext {
    pub wallet_identity: Vec<u8>,
    pub issuer_identity: Option<Vec<u8>>,
    pub key_generation: u64,
    pub transaction_id: Option<Vec<u8>>,
    pub session_id: Option<Vec<u8>>,
    pub audience: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
    pub created_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
    pub transcript_hash: Option<[u8; 32]>,
}

#[derive(Clone)]
pub struct UnsignedEnvelope {
    pub purpose: HybridPurpose,
    pub context: HybridContext,
    pub payload: Vec<u8>,
    pub disclosures: Vec<Vec<u8>>,
    pub classical_kid: String,
    pub pq_kid: String,
    pub generation: u64,
}

pub struct EnvelopeSignatures {
    pub classical: Vec<u8>,
    pub post_quantum: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicComponents {
    pub classical: Vec<u8>,
    pub post_quantum: Vec<u8>,
}

#[allow(dead_code)]
pub struct VerificationParameters<'a> {
    pub purpose: HybridPurpose,
    pub context: &'a HybridContext,
    pub classical_kid: &'a str,
    pub pq_kid: &'a str,
    pub classical_public_key: &'a [u8],
    pub pq_public_key: &'a [u8],
    pub generation: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[allow(dead_code)]
pub enum HybridCodecError {
    #[error("hybrid field exceeds its bound")]
    Oversized,
    #[error("hybrid TBS component exceeds the u32 length encoding")]
    LengthOverflow,
    #[error("hybrid envelope is malformed")]
    Malformed,
    #[error("hybrid envelope has duplicate fields")]
    DuplicateField,
    #[error("hybrid envelope is not canonical CBOR or has trailing bytes")]
    NonCanonical,
    #[error("hybrid envelope uses an unsupported version or profile")]
    Unsupported,
    #[error("hybrid envelope is missing a required component")]
    Missing,
    #[error("hybrid logical key generation does not match")]
    GenerationMismatch,
    #[error("hybrid ES256 signature is invalid")]
    ClassicalSignature,
    #[error("hybrid ML-DSA-65 signature is invalid")]
    PostQuantumSignature,
}

impl HybridContext {
    fn encode_for(&self, purpose: HybridPurpose) -> Result<Vec<u8>, HybridCodecError> {
        self.validate_common()?;
        self.validate_for(purpose)?;
        let mut encoded = Vec::with_capacity(256);
        encoded.extend_from_slice(CONTEXT_DOMAIN);
        encode_context_field(&mut encoded, 1, Some(&self.wallet_identity))?;
        encode_context_field(&mut encoded, 2, self.issuer_identity.as_deref())?;
        encode_context_field(&mut encoded, 3, Some(&self.key_generation.to_be_bytes()))?;
        encode_context_field(&mut encoded, 4, self.transaction_id.as_deref())?;
        encode_context_field(&mut encoded, 5, self.session_id.as_deref())?;
        encode_context_field(&mut encoded, 6, self.audience.as_deref())?;
        encode_context_field(&mut encoded, 7, Some(&self.nonce))?;
        encode_context_field(
            &mut encoded,
            8,
            Some(&self.created_at_epoch_seconds.to_be_bytes()),
        )?;
        encode_context_field(
            &mut encoded,
            9,
            Some(&self.expires_at_epoch_seconds.to_be_bytes()),
        )?;
        encode_context_field(
            &mut encoded,
            10,
            self.transcript_hash.as_ref().map(<[u8; 32]>::as_slice),
        )?;
        Ok(encoded)
    }

    fn validate_common(&self) -> Result<(), HybridCodecError> {
        require_nonempty_bounded(&self.wallet_identity)?;
        validate_optional(self.issuer_identity.as_deref())?;
        validate_optional(self.transaction_id.as_deref())?;
        validate_optional(self.session_id.as_deref())?;
        validate_optional(self.audience.as_deref())?;
        if self.key_generation == 0 {
            return Err(HybridCodecError::GenerationMismatch);
        }
        if !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&self.nonce.len())
            || self.created_at_epoch_seconds >= self.expires_at_epoch_seconds
        {
            return Err(HybridCodecError::Malformed);
        }
        Ok(())
    }

    fn validate_for(&self, purpose: HybridPurpose) -> Result<(), HybridCodecError> {
        match purpose {
            HybridPurpose::WalletExportV1 | HybridPurpose::WalletRecoveryV1 => {
                require_absent(self.issuer_identity.as_ref())?;
                require_absent(self.transaction_id.as_ref())?;
                require_absent(self.session_id.as_ref())?;
                require_absent(self.audience.as_ref())?;
                require_absent(self.transcript_hash.as_ref())
            }
            HybridPurpose::PrivateProviderMessageV1 => {
                require_present(self.session_id.as_ref())?;
                require_present(self.audience.as_ref())?;
                require_present(self.transcript_hash.as_ref())
            }
            HybridPurpose::TestSdJwtWrapperV1 | HybridPurpose::TestMdocWrapperV1 => {
                require_present(self.issuer_identity.as_ref())?;
                require_present(self.transaction_id.as_ref())?;
                require_present(self.audience.as_ref())?;
                if self.session_id.is_some() {
                    require_present(self.transcript_hash.as_ref())?;
                }
                Ok(())
            }
        }
    }
}

pub fn tbs(unsigned: &UnsignedEnvelope) -> Result<Vec<u8>, HybridCodecError> {
    let committed_payload = committed_payload(unsigned)?;
    build_tbs(unsigned.purpose, &unsigned.context, &committed_payload)
}

pub fn build_tbs(
    purpose: HybridPurpose,
    context: &HybridContext,
    payload: &[u8],
) -> Result<Vec<u8>, HybridCodecError> {
    if payload.len() > MAX_FIELD_BYTES {
        return Err(HybridCodecError::Oversized);
    }
    let encoded_context = context.encode_for(purpose)?;
    let mut output = Vec::with_capacity(
        DOMAIN.len()
            + PROFILE.len()
            + purpose.id().len()
            + encoded_context.len()
            + payload.len()
            + 16,
    );
    output.extend_from_slice(DOMAIN);
    append_component(&mut output, PROFILE.as_bytes())?;
    append_component(&mut output, purpose.id().as_bytes())?;
    append_component(&mut output, &encoded_context)?;
    append_component(&mut output, payload)?;
    Ok(output)
}

/// Encode the standalone public-key container frozen by `EUWallet` PR #103.
pub fn encode_public_key_envelope(
    classical: &[u8],
    post_quantum: &[u8],
) -> Result<Vec<u8>, HybridCodecError> {
    if classical.len() != 65
        || classical.first().copied() != Some(0x04)
        || post_quantum.len() != pq_backend::PUBLIC_KEY_BYTES
    {
        return Err(HybridCodecError::Malformed);
    }
    encode_component_envelope(vec![
        pair(1, Value::Integer(Integer::from(VERSION))),
        pair(2, Value::Integer(Integer::from(1))),
        pair(3, Value::Text(PROFILE.into())),
        pair(4, Value::Bytes(classical.to_vec())),
        pair(5, Value::Bytes(post_quantum.to_vec())),
    ])
}

#[allow(dead_code)]
pub fn decode_public_key_envelope(
    encoded: &[u8],
) -> Result<HybridPublicComponents, HybridCodecError> {
    let fields = decode_component_envelope(encoded, 5)?;
    if integer(&fields[0].1)? != VERSION
        || integer(&fields[1].1)? != 1
        || text(&fields[2].1)? != PROFILE
    {
        return Err(HybridCodecError::Unsupported);
    }
    let classical = bytes(&fields[3].1)?.to_vec();
    let post_quantum = bytes(&fields[4].1)?.to_vec();
    if classical.len() != 65
        || classical.first().copied() != Some(0x04)
        || post_quantum.len() != pq_backend::PUBLIC_KEY_BYTES
    {
        return Err(HybridCodecError::Malformed);
    }
    Ok(HybridPublicComponents {
        classical,
        post_quantum,
    })
}

/// Encode the standalone atomic dual-signature container frozen by `EUWallet` PR #103.
#[allow(dead_code)]
pub fn encode_signature_envelope(
    purpose: HybridPurpose,
    signatures: &EnvelopeSignatures,
) -> Result<Vec<u8>, HybridCodecError> {
    if signatures.classical.len() != 64
        || signatures.post_quantum.len() != pq_backend::SIGNATURE_BYTES
    {
        return Err(HybridCodecError::Missing);
    }
    encode_component_envelope(vec![
        pair(1, Value::Integer(Integer::from(VERSION))),
        pair(2, Value::Integer(Integer::from(2))),
        pair(3, Value::Text(PROFILE.into())),
        pair(4, Value::Bytes(signatures.classical.clone())),
        pair(5, Value::Bytes(signatures.post_quantum.clone())),
        pair(6, Value::Text(purpose.id().into())),
    ])
}

#[allow(dead_code)]
pub fn decode_signature_envelope(
    encoded: &[u8],
    expected_purpose: HybridPurpose,
) -> Result<EnvelopeSignatures, HybridCodecError> {
    let fields = decode_component_envelope(encoded, 6)?;
    let purpose = HybridPurpose::try_from(text(&fields[5].1)?)?;
    if integer(&fields[0].1)? != VERSION
        || integer(&fields[1].1)? != 2
        || text(&fields[2].1)? != PROFILE
        || purpose != expected_purpose
    {
        return Err(HybridCodecError::Unsupported);
    }
    let signatures = EnvelopeSignatures {
        classical: bytes(&fields[3].1)?.to_vec(),
        post_quantum: bytes(&fields[4].1)?.to_vec(),
    };
    if signatures.classical.len() != 64
        || signatures.post_quantum.len() != pq_backend::SIGNATURE_BYTES
    {
        return Err(HybridCodecError::Missing);
    }
    Ok(signatures)
}

pub fn encode(
    unsigned: &UnsignedEnvelope,
    signatures: &EnvelopeSignatures,
) -> Result<Vec<u8>, HybridCodecError> {
    if signatures.classical.len() != 64
        || signatures.post_quantum.len() != pq_backend::SIGNATURE_BYTES
    {
        return Err(HybridCodecError::Missing);
    }
    require_nonempty_bounded(&unsigned.payload)?;
    for disclosure in &unsigned.disclosures {
        require_nonempty_bounded(disclosure)?;
    }
    for kid in [&unsigned.classical_kid, &unsigned.pq_kid] {
        if kid.is_empty() {
            return Err(HybridCodecError::Malformed);
        }
        if kid.len() > MAX_KEY_ID_BYTES {
            return Err(HybridCodecError::Oversized);
        }
    }
    if unsigned.generation == 0 {
        return Err(HybridCodecError::GenerationMismatch);
    }
    let value = Value::Map(vec![
        pair(1, Value::Integer(Integer::from(VERSION))),
        pair(2, Value::Text(PROFILE.into())),
        pair(3, Value::Text(unsigned.purpose.id().into())),
        pair(4, Value::Text(FORMAT.into())),
        pair(5, Value::Bytes(unsigned.payload.clone())),
        pair(
            6,
            Value::Array(
                unsigned
                    .disclosures
                    .iter()
                    .cloned()
                    .map(Value::Bytes)
                    .collect(),
            ),
        ),
        pair(7, Value::Text(unsigned.classical_kid.clone())),
        pair(8, Value::Text(unsigned.pq_kid.clone())),
        pair(9, Value::Integer(Integer::from(unsigned.generation))),
        pair(10, Value::Bytes(signatures.classical.clone())),
        pair(11, Value::Bytes(signatures.post_quantum.clone())),
    ]);
    let mut encoded = ENVELOPE_MAGIC.to_vec();
    ciborium::ser::into_writer(&value, &mut encoded).map_err(|_| HybridCodecError::Malformed)?;
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(HybridCodecError::Oversized);
    }
    Ok(encoded)
}

#[allow(dead_code)]
pub fn verify(
    encoded: &[u8],
    parameters: &VerificationParameters<'_>,
) -> Result<(), HybridCodecError> {
    let (unsigned, signatures) = decode(encoded, parameters.purpose, parameters.context)?;
    if unsigned.generation != parameters.generation
        || unsigned.context.key_generation != parameters.generation
    {
        return Err(HybridCodecError::GenerationMismatch);
    }
    if unsigned.classical_kid != parameters.classical_kid || unsigned.pq_kid != parameters.pq_kid {
        return Err(HybridCodecError::GenerationMismatch);
    }
    let signed = tbs(&unsigned)?;
    let classical_key = VerifyingKey::from_sec1_bytes(parameters.classical_public_key)
        .map_err(|_| HybridCodecError::ClassicalSignature)?;
    let classical_signature = Signature::from_slice(&signatures.classical)
        .map_err(|_| HybridCodecError::ClassicalSignature)?;
    classical_key
        .verify(&signed, &classical_signature)
        .map_err(|_| HybridCodecError::ClassicalSignature)?;
    pq_backend::verify_signature(parameters.pq_public_key, &signed, &signatures.post_quantum)
        .map_err(|_| HybridCodecError::PostQuantumSignature)
}

fn decode(
    encoded: &[u8],
    expected_purpose: HybridPurpose,
    context: &HybridContext,
) -> Result<(UnsignedEnvelope, EnvelopeSignatures), HybridCodecError> {
    if encoded.len() > MAX_ENVELOPE_BYTES || !encoded.starts_with(ENVELOPE_MAGIC) {
        return Err(HybridCodecError::Oversized);
    }
    let body = &encoded[ENVELOPE_MAGIC.len()..];
    let mut cursor = Cursor::new(body);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| HybridCodecError::Malformed)?;
    if usize::try_from(cursor.position()).ok() != Some(body.len()) {
        return Err(HybridCodecError::NonCanonical);
    }
    let mut canonical = Vec::new();
    ciborium::ser::into_writer(&value, &mut canonical).map_err(|_| HybridCodecError::Malformed)?;
    if canonical != body {
        return Err(HybridCodecError::NonCanonical);
    }
    let Value::Map(entries) = value else {
        return Err(HybridCodecError::Malformed);
    };
    let mut seen = BTreeSet::new();
    let mut fields = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let Value::Integer(key) = key else {
            return Err(HybridCodecError::Malformed);
        };
        let key = u64::try_from(key).map_err(|_| HybridCodecError::Malformed)?;
        if !seen.insert(key) {
            return Err(HybridCodecError::DuplicateField);
        }
        fields.push((key, value));
    }
    if fields.len() != 11 || fields.iter().map(|(key, _)| *key).ne(1..=11) {
        return Err(HybridCodecError::Missing);
    }
    let version = integer(&fields[0].1)?;
    let profile = text(&fields[1].1)?;
    let purpose = HybridPurpose::try_from(text(&fields[2].1)?)?;
    let format = text(&fields[3].1)?;
    if version != VERSION || profile != PROFILE || purpose != expected_purpose || format != FORMAT {
        return Err(HybridCodecError::Unsupported);
    }
    let payload = bytes(&fields[4].1)?.to_vec();
    require_nonempty_bounded(&payload)?;
    let disclosures = byte_array(&fields[5].1)?;
    for disclosure in &disclosures {
        require_nonempty_bounded(disclosure)?;
    }
    let classical_kid = text(&fields[6].1)?.to_owned();
    let pq_kid = text(&fields[7].1)?.to_owned();
    for kid in [&classical_kid, &pq_kid] {
        if kid.is_empty() {
            return Err(HybridCodecError::Malformed);
        }
        if kid.len() > MAX_KEY_ID_BYTES {
            return Err(HybridCodecError::Oversized);
        }
    }
    let generation = integer(&fields[8].1)?;
    if generation == 0 {
        return Err(HybridCodecError::GenerationMismatch);
    }
    let classical = bytes(&fields[9].1)?.to_vec();
    let post_quantum = bytes(&fields[10].1)?.to_vec();
    if classical.len() != 64 || post_quantum.len() != pq_backend::SIGNATURE_BYTES {
        return Err(HybridCodecError::Missing);
    }
    Ok((
        UnsignedEnvelope {
            purpose,
            context: context.clone(),
            payload,
            disclosures,
            classical_kid,
            pq_kid,
            generation,
        },
        EnvelopeSignatures {
            classical,
            post_quantum,
        },
    ))
}

fn encode_component_envelope(fields: Vec<(Value, Value)>) -> Result<Vec<u8>, HybridCodecError> {
    let mut encoded = ENVELOPE_MAGIC.to_vec();
    ciborium::ser::into_writer(&Value::Map(fields), &mut encoded)
        .map_err(|_| HybridCodecError::Malformed)?;
    if encoded.len() > MAX_COMPONENT_ENVELOPE_BYTES {
        return Err(HybridCodecError::Oversized);
    }
    Ok(encoded)
}

fn decode_component_envelope(
    encoded: &[u8],
    expected_fields: usize,
) -> Result<Vec<(u64, Value)>, HybridCodecError> {
    if encoded.len() > MAX_COMPONENT_ENVELOPE_BYTES {
        return Err(HybridCodecError::Oversized);
    }
    let body = encoded
        .strip_prefix(ENVELOPE_MAGIC)
        .ok_or(HybridCodecError::Malformed)?;
    let mut cursor = Cursor::new(body);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| HybridCodecError::Malformed)?;
    if usize::try_from(cursor.position()).ok() != Some(body.len()) {
        return Err(HybridCodecError::NonCanonical);
    }
    let mut canonical = Vec::new();
    ciborium::ser::into_writer(&value, &mut canonical).map_err(|_| HybridCodecError::Malformed)?;
    if canonical != body {
        return Err(HybridCodecError::NonCanonical);
    }
    let Value::Map(entries) = value else {
        return Err(HybridCodecError::Malformed);
    };
    if entries.len() != expected_fields {
        return Err(HybridCodecError::Missing);
    }
    let mut fields = Vec::with_capacity(entries.len());
    for (index, (key, value)) in entries.into_iter().enumerate() {
        let Value::Integer(key) = key else {
            return Err(HybridCodecError::Malformed);
        };
        let key = u64::try_from(key).map_err(|_| HybridCodecError::Malformed)?;
        if key != u64::try_from(index + 1).map_err(|_| HybridCodecError::Malformed)? {
            return Err(HybridCodecError::DuplicateField);
        }
        fields.push((key, value));
    }
    Ok(fields)
}

fn append_component(output: &mut Vec<u8>, component: &[u8]) -> Result<(), HybridCodecError> {
    let length = u32::try_from(component.len()).map_err(|_| HybridCodecError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(component);
    Ok(())
}

fn encode_context_field(
    output: &mut Vec<u8>,
    tag: u8,
    value: Option<&[u8]>,
) -> Result<(), HybridCodecError> {
    output.push(tag);
    append_component(output, value.unwrap_or_default())
}

fn require_nonempty_bounded(value: &[u8]) -> Result<(), HybridCodecError> {
    if value.is_empty() {
        return Err(HybridCodecError::Malformed);
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(HybridCodecError::Oversized);
    }
    Ok(())
}

fn validate_optional(value: Option<&[u8]>) -> Result<(), HybridCodecError> {
    if let Some(value) = value {
        require_nonempty_bounded(value)?;
    }
    Ok(())
}

fn require_present<T>(value: Option<&T>) -> Result<(), HybridCodecError> {
    if value.is_none() {
        return Err(HybridCodecError::Missing);
    }
    Ok(())
}

fn require_absent<T>(value: Option<&T>) -> Result<(), HybridCodecError> {
    if value.is_some() {
        return Err(HybridCodecError::Unsupported);
    }
    Ok(())
}

fn committed_payload(unsigned: &UnsignedEnvelope) -> Result<Vec<u8>, HybridCodecError> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![
            pair(1, Value::Bytes(unsigned.payload.clone())),
            pair(
                2,
                Value::Array(
                    unsigned
                        .disclosures
                        .iter()
                        .cloned()
                        .map(Value::Bytes)
                        .collect(),
                ),
            ),
        ]),
        &mut encoded,
    )
    .map_err(|_| HybridCodecError::Malformed)?;
    Ok(encoded)
}

fn pair(key: u64, value: Value) -> (Value, Value) {
    (Value::Integer(Integer::from(key)), value)
}

fn integer(value: &Value) -> Result<u64, HybridCodecError> {
    let Value::Integer(value) = value else {
        return Err(HybridCodecError::Malformed);
    };
    u64::try_from(*value).map_err(|_| HybridCodecError::Malformed)
}

fn text(value: &Value) -> Result<&str, HybridCodecError> {
    let Value::Text(value) = value else {
        return Err(HybridCodecError::Malformed);
    };
    Ok(value)
}

fn bytes(value: &Value) -> Result<&[u8], HybridCodecError> {
    let Value::Bytes(value) = value else {
        return Err(HybridCodecError::Malformed);
    };
    Ok(value)
}

fn byte_array(value: &Value) -> Result<Vec<Vec<u8>>, HybridCodecError> {
    let Value::Array(values) = value else {
        return Err(HybridCodecError::Malformed);
    };
    values
        .iter()
        .map(|value| bytes(value).map(<[u8]>::to_vec))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use libcrux_ml_dsa::ml_dsa_65::{generate_key_pair, sign};
    use p256::ecdsa::{
        SigningKey,
        signature::{Signer, Verifier},
    };
    use serde_json::json;
    use zeroize::Zeroize;

    use super::*;

    struct Fixture {
        unsigned: UnsignedEnvelope,
        encoded: Vec<u8>,
        classical_public_key: Vec<u8>,
        pq_public_key: Vec<u8>,
    }

    fn issuer_context(generation: u64) -> HybridContext {
        HybridContext {
            wallet_identity: b"wallet-holder-thumbprint".to_vec(),
            issuer_identity: Some(b"https://issuer.example".to_vec()),
            key_generation: generation,
            transaction_id: Some(b"transaction-123".to_vec()),
            session_id: None,
            audience: Some(b"https://issuer.example".to_vec()),
            nonce: (0_u8..32).collect(),
            created_at_epoch_seconds: 1_700_000_000,
            expires_at_epoch_seconds: 1_700_003_600,
            transcript_hash: None,
        }
    }

    fn export_context() -> HybridContext {
        HybridContext {
            wallet_identity: b"wallet-123".to_vec(),
            issuer_identity: None,
            key_generation: 7,
            transaction_id: None,
            session_id: None,
            audience: None,
            nonce: (0_u8..16).collect(),
            created_at_epoch_seconds: 1_700_000_000,
            expires_at_epoch_seconds: 1_700_003_600,
            transcript_hash: None,
        }
    }

    fn vector_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors")
            .join(name)
    }

    fn assert_or_update_vector(name: &str, contents: &str) {
        let path = vector_path(name);
        if std::env::var_os("UPDATE_HYBRID_PQ_VECTORS").is_some() {
            fs::write(&path, format!("{contents}\n")).expect("write generated vector");
        }
        assert_eq!(
            fs::read_to_string(path)
                .expect("shared vector exists")
                .trim(),
            contents
        );
    }

    fn apply_vector_operations(mut bytes: Vec<u8>, operations: &[serde_json::Value]) -> Vec<u8> {
        fn usize_field(operation: &serde_json::Value, field: &str) -> usize {
            usize::try_from(operation[field].as_u64().expect("unsigned mutation field"))
                .expect("mutation field fits usize")
        }

        for operation in operations {
            let kind = operation["op"].as_str().expect("mutation operation");
            match kind {
                "xor" => {
                    let offset = usize_field(operation, "offset");
                    bytes[offset] ^=
                        u8::try_from(operation["value"].as_u64().expect("unsigned xor value"))
                            .expect("xor value fits u8");
                }
                "truncate" => {
                    let count = usize_field(operation, "count");
                    bytes.truncate(bytes.len() - count);
                }
                "append" => bytes.extend_from_slice(
                    &hex::decode(operation["hex"].as_str().expect("append hex"))
                        .expect("valid append hex"),
                ),
                "replace" => {
                    let offset = usize_field(operation, "offset");
                    let delete = usize_field(operation, "delete");
                    bytes.splice(
                        offset..offset + delete,
                        hex::decode(operation["hex"].as_str().expect("replace hex"))
                            .expect("valid replace hex"),
                    );
                }
                "remove" => {
                    let offset = usize_field(operation, "offset");
                    let count = usize_field(operation, "count");
                    bytes.drain(offset..offset + count);
                }
                _ => panic!("unknown mutation operation"),
            }
        }
        bytes
    }

    fn fixture() -> Fixture {
        let classical_key =
            SigningKey::from_bytes((&[7_u8; 32]).into()).expect("fixed P-256 test key");
        let pq = pq_backend::generate().expect("system CSPRNG");
        let unsigned = UnsignedEnvelope {
            purpose: HybridPurpose::TestSdJwtWrapperV1,
            context: issuer_context(4),
            payload: b"canonical credential payload".to_vec(),
            disclosures: vec![b"canonical disclosure".to_vec()],
            classical_kid: "classical-kid".into(),
            pq_kid: "pq-kid".into(),
            generation: 4,
        };
        let signed = tbs(&unsigned).expect("TBS");
        let classical: Signature = classical_key.sign(&signed);
        classical_key
            .verifying_key()
            .verify(&signed, &classical)
            .expect("classical fixture");
        let post_quantum = pq_backend::sign_once(&pq.secret_key, &signed).expect("PQ fixture");
        let encoded = encode(
            &unsigned,
            &EnvelopeSignatures {
                classical: classical.to_bytes().to_vec(),
                post_quantum,
            },
        )
        .expect("envelope");
        Fixture {
            unsigned,
            encoded,
            classical_public_key: classical_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            pq_public_key: pq.public_key,
        }
    }

    fn mutate_field(encoded: &[u8], field: u64, replacement: Value) -> Vec<u8> {
        let body = encoded
            .strip_prefix(ENVELOPE_MAGIC)
            .expect("experimental envelope prefix");
        let Value::Map(mut entries) = ciborium::de::from_reader(body).expect("fixture envelope")
        else {
            panic!("fixture is a map");
        };
        let (_, value) = entries
            .iter_mut()
            .find(|(key, _)| {
                matches!(key, Value::Integer(value) if u64::try_from(*value) == Ok(field))
            })
            .expect("fixture field");
        *value = replacement;
        let mut result = ENVELOPE_MAGIC.to_vec();
        ciborium::ser::into_writer(&Value::Map(entries), &mut result).expect("mutated envelope");
        result
    }

    fn verify_fixture(fixture: &Fixture, encoded: &[u8], context: &HybridContext, generation: u64) {
        verify_result(fixture, encoded, context, generation).expect("both signatures valid");
    }

    fn verify_result(
        fixture: &Fixture,
        encoded: &[u8],
        context: &HybridContext,
        generation: u64,
    ) -> Result<(), HybridCodecError> {
        verify(
            encoded,
            &VerificationParameters {
                purpose: fixture.unsigned.purpose,
                context,
                classical_kid: &fixture.unsigned.classical_kid,
                pq_kid: &fixture.unsigned.pq_kid,
                classical_public_key: &fixture.classical_public_key,
                pq_public_key: &fixture.pq_public_key,
                generation,
            },
        )
    }

    fn decode_result(
        fixture: &Fixture,
        encoded: &[u8],
    ) -> Result<(UnsignedEnvelope, EnvelopeSignatures), HybridCodecError> {
        decode(encoded, fixture.unsigned.purpose, &fixture.unsigned.context)
    }

    #[test]
    fn requires_both_valid_signatures_for_the_same_tbs() {
        let fixture = fixture();
        verify_fixture(
            &fixture,
            &fixture.encoded,
            &fixture.unsigned.context,
            fixture.unsigned.generation,
        );

        for field in [10, 11] {
            let mut signature = match field {
                10 => vec![0_u8; 64],
                _ => vec![0_u8; pq_backend::SIGNATURE_BYTES],
            };
            signature[0] = 1;
            let invalid = mutate_field(&fixture.encoded, field, Value::Bytes(signature));
            assert!(
                verify_result(
                    &fixture,
                    &invalid,
                    &fixture.unsigned.context,
                    fixture.unsigned.generation,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn missing_or_unsupported_components_fail_closed() {
        let fixture = fixture();
        let Value::Map(mut entries) = ciborium::de::from_reader(
            fixture
                .encoded
                .strip_prefix(ENVELOPE_MAGIC)
                .expect("experimental envelope prefix"),
        )
        .expect("fixture envelope") else {
            panic!("fixture is a map");
        };
        entries.pop();
        let mut missing = ENVELOPE_MAGIC.to_vec();
        ciborium::ser::into_writer(&Value::Map(entries), &mut missing).expect("missing field");
        assert!(decode_result(&fixture, &missing).is_err());

        for (field, value) in [
            (1, Value::Integer(Integer::from(2_u64))),
            (2, Value::Text("unknown-profile".into())),
            (3, Value::Text("production-sd-jwt".into())),
        ] {
            assert!(
                decode_result(&fixture, &mutate_field(&fixture.encoded, field, value)).is_err()
            );
        }
        assert!(decode_result(&fixture, b"header.payload.signature").is_err());
    }

    #[test]
    fn payload_disclosure_context_and_generation_mutations_fail() {
        let fixture = fixture();
        let changed_payload = mutate_field(&fixture.encoded, 5, Value::Bytes(b"changed".to_vec()));
        let changed_disclosures = mutate_field(
            &fixture.encoded,
            6,
            Value::Array(vec![Value::Bytes(b"changed".to_vec())]),
        );
        for encoded in [&changed_payload, &changed_disclosures] {
            assert!(
                verify_result(
                    &fixture,
                    encoded,
                    &fixture.unsigned.context,
                    fixture.unsigned.generation,
                )
                .is_err()
            );
        }
        let mut changed_context = fixture.unsigned.context.clone();
        changed_context.audience = Some(b"https://attacker.example".to_vec());
        assert!(
            verify_result(
                &fixture,
                &fixture.encoded,
                &changed_context,
                fixture.unsigned.generation,
            )
            .is_err()
        );
        assert_eq!(
            verify_result(
                &fixture,
                &fixture.encoded,
                &fixture.unsigned.context,
                fixture.unsigned.generation + 1,
            ),
            Err(HybridCodecError::GenerationMismatch)
        );
    }

    #[test]
    fn malformed_noncanonical_duplicate_trailing_and_oversized_cbor_fail() {
        let fixture = fixture();
        let mut trailing = fixture.encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_result(&fixture, &trailing),
            Err(HybridCodecError::NonCanonical)
        ));

        let Value::Map(mut entries) = ciborium::de::from_reader(
            fixture
                .encoded
                .strip_prefix(ENVELOPE_MAGIC)
                .expect("experimental envelope prefix"),
        )
        .expect("fixture envelope") else {
            panic!("fixture is a map");
        };
        entries.push(entries[0].clone());
        let mut duplicate = ENVELOPE_MAGIC.to_vec();
        ciborium::ser::into_writer(&Value::Map(entries), &mut duplicate).expect("duplicate map");
        assert!(matches!(
            decode_result(&fixture, &duplicate),
            Err(HybridCodecError::DuplicateField)
        ));

        assert!(matches!(
            decode_result(&fixture, &vec![0_u8; MAX_ENVELOPE_BYTES + 1]),
            Err(HybridCodecError::Oversized)
        ));
        assert!(decode_result(&fixture, &[0xbf, 0xff]).is_err());
    }

    #[test]
    fn consumes_the_exact_euwallet_tbs_vectors() {
        let export = build_tbs(HybridPurpose::WalletExportV1, &export_context(), b"payload")
            .expect("EUWallet export vector");
        let recovery = build_tbs(
            HybridPurpose::WalletRecoveryV1,
            &export_context(),
            b"payload",
        )
        .expect("EUWallet recovery vector");
        assert_eq!(
            hex::encode(&export),
            include_str!("../tests/vectors/hybrid-pq-v1-export-tbs.hex").trim()
        );
        assert_eq!(
            hex::encode(&recovery),
            include_str!("../tests/vectors/hybrid-pq-v1-recovery-tbs.hex").trim()
        );
        assert_ne!(export, recovery);
        assert_eq!(
            include_str!("../tests/vectors/hybrid-pq-v2-invalid-profile-tbs.hex").trim(),
            hex::encode(export).replacen("70712d7631", "70712d7632", 1)
        );
    }

    #[test]
    fn frozen_context_policy_rejects_missing_or_misplaced_bindings() {
        let mut context = issuer_context(4);
        context.issuer_identity = None;
        assert_eq!(
            build_tbs(HybridPurpose::TestSdJwtWrapperV1, &context, b"payload"),
            Err(HybridCodecError::Missing)
        );

        let mut context = export_context();
        context.audience = Some(b"network-peer".to_vec());
        assert_eq!(
            build_tbs(HybridPurpose::WalletExportV1, &context, b"payload"),
            Err(HybridCodecError::Unsupported)
        );

        let mut context = issuer_context(0);
        context.key_generation = 0;
        assert_eq!(
            build_tbs(HybridPurpose::TestSdJwtWrapperV1, &context, b"payload"),
            Err(HybridCodecError::GenerationMismatch)
        );
    }

    #[test]
    fn matches_euwallet_pr103_component_envelope_bytes() {
        let mut classical_key = vec![0x11; 65];
        classical_key[0] = 0x04;
        let pq_key = vec![0x22; pq_backend::PUBLIC_KEY_BYTES];
        let encoded_key =
            encode_public_key_envelope(&classical_key, &pq_key).expect("public-key envelope");
        let mut expected_key = ENVELOPE_MAGIC.to_vec();
        expected_key.extend_from_slice(&[0xa5, 0x01, 0x01, 0x02, 0x01, 0x03, 0x75]);
        expected_key.extend_from_slice(PROFILE.as_bytes());
        expected_key.extend_from_slice(&[0x04, 0x58, 0x41]);
        expected_key.extend_from_slice(&classical_key);
        expected_key.extend_from_slice(&[0x05, 0x59, 0x07, 0xa0]);
        expected_key.extend_from_slice(&pq_key);
        assert_eq!(encoded_key, expected_key);
        assert_eq!(
            decode_public_key_envelope(&encoded_key),
            Ok(HybridPublicComponents {
                classical: classical_key,
                post_quantum: pq_key,
            })
        );

        let signatures = EnvelopeSignatures {
            classical: vec![0x33; 64],
            post_quantum: vec![0x44; pq_backend::SIGNATURE_BYTES],
        };
        let encoded_signature =
            encode_signature_envelope(HybridPurpose::TestSdJwtWrapperV1, &signatures)
                .expect("signature envelope");
        let mut expected_signature = ENVELOPE_MAGIC.to_vec();
        expected_signature.extend_from_slice(&[0xa6, 0x01, 0x01, 0x02, 0x02, 0x03, 0x75]);
        expected_signature.extend_from_slice(PROFILE.as_bytes());
        expected_signature.extend_from_slice(&[0x04, 0x58, 0x40]);
        expected_signature.extend_from_slice(&signatures.classical);
        expected_signature.extend_from_slice(&[0x05, 0x59, 0x0c, 0xed]);
        expected_signature.extend_from_slice(&signatures.post_quantum);
        expected_signature.extend_from_slice(&[0x06, 0x76]);
        expected_signature.extend_from_slice(HybridPurpose::TestSdJwtWrapperV1.id().as_bytes());
        assert_eq!(encoded_signature, expected_signature);
        let decoded =
            decode_signature_envelope(&encoded_signature, HybridPurpose::TestSdJwtWrapperV1)
                .expect("signature envelope round trip");
        assert_eq!(decoded.classical, signatures.classical);
        assert_eq!(decoded.post_quantum, signatures.post_quantum);
    }

    #[test]
    fn euwallet_component_envelopes_reject_noncanonical_and_downgraded_input() {
        let mut classical_key = vec![0x11; 65];
        classical_key[0] = 0x04;
        let pq_key = vec![0x22; pq_backend::PUBLIC_KEY_BYTES];
        let encoded =
            encode_public_key_envelope(&classical_key, &pq_key).expect("public-key envelope");

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_public_key_envelope(&trailing),
            Err(HybridCodecError::NonCanonical)
        );

        let mut wrong_kind = encoded.clone();
        wrong_kind[ENVELOPE_MAGIC.len() + 4] = 2;
        assert_eq!(
            decode_public_key_envelope(&wrong_kind),
            Err(HybridCodecError::Unsupported)
        );

        let signatures = EnvelopeSignatures {
            classical: vec![0x33; 64],
            post_quantum: vec![0x44; pq_backend::SIGNATURE_BYTES],
        };
        let mut signature =
            encode_signature_envelope(HybridPurpose::TestSdJwtWrapperV1, &signatures)
                .expect("signature envelope");
        signature.truncate(signature.len() - HybridPurpose::TestSdJwtWrapperV1.id().len() - 2);
        assert!(decode_signature_envelope(&signature, HybridPurpose::TestSdJwtWrapperV1).is_err());

        assert!(matches!(
            decode_public_key_envelope(&vec![0; MAX_COMPONENT_ENVELOPE_BYTES + 1]),
            Err(HybridCodecError::Oversized)
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn consumes_deterministic_real_signature_wrapper_corpus() {
        let classical_key =
            SigningKey::from_bytes((&[7_u8; 32]).into()).expect("fixed vector P-256 key");
        let mut pq_key_pair = generate_key_pair([0x42; 32]);
        let unsigned = UnsignedEnvelope {
            purpose: HybridPurpose::TestSdJwtWrapperV1,
            context: issuer_context(9),
            payload: b"shared experimental credential payload".to_vec(),
            disclosures: vec![
                b"shared disclosure one".to_vec(),
                b"shared disclosure two".to_vec(),
            ],
            classical_kid: "shared-classical-kid-v1".into(),
            pq_kid: "shared-pq-kid-v1".into(),
            generation: 9,
        };
        let signed = tbs(&unsigned).expect("shared wrapper TBS");
        assert_eq!(
            hex::encode(&signed),
            include_str!("../tests/vectors/hybrid-pq-v1-component-tbs.hex").trim(),
            "the wrapper corpus commits to the shared component TBS"
        );
        let classical_signature: Signature = classical_key.sign(&signed);
        let pq_signature = sign(&pq_key_pair.signing_key, &signed, &[], [0x24; 32])
            .expect("fixed-randomness ML-DSA vector")
            .as_slice()
            .to_vec();
        let classical_public_key = classical_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let pq_public_key = pq_key_pair.verification_key.as_slice().to_vec();
        let encoded = encode(
            &unsigned,
            &EnvelopeSignatures {
                classical: classical_signature.to_bytes().to_vec(),
                post_quantum: pq_signature,
            },
        )
        .expect("shared wrapper envelope");
        pq_key_pair.signing_key.as_mut_slice().zeroize();

        assert_or_update_vector("hybrid-pq-v1-wrapper-envelope.hex", &hex::encode(&encoded));

        let find = |needle: &[u8]| {
            encoded
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("wrapper corpus offset")
        };
        let magic_len = ENVELOPE_MAGIC.len();
        let version_offset = magic_len + 2;
        let profile_offset = find(PROFILE.as_bytes());
        let purpose_offset = find(unsigned.purpose.id().as_bytes());
        let format_offset = find(FORMAT.as_bytes());
        let payload_offset = find(&unsigned.payload);
        let first_disclosure_offset = find(&unsigned.disclosures[0]);
        let array_head_offset = first_disclosure_offset - 2;
        let disclosure_region = array_head_offset + 1
            ..first_disclosure_offset
                + unsigned.disclosures[0].len()
                + 1
                + unsigned.disclosures[1].len();
        let mut swapped_disclosures = Vec::new();
        for disclosure in [&unsigned.disclosures[1], &unsigned.disclosures[0]] {
            swapped_disclosures.push(0x40 + u8::try_from(disclosure.len()).expect("short"));
            swapped_disclosures.extend_from_slice(disclosure);
        }
        let classical_kid_offset = find(unsigned.classical_kid.as_bytes());
        let pq_kid_offset = find(unsigned.pq_kid.as_bytes());
        let generation_key_offset = pq_kid_offset + unsigned.pq_kid.len();
        let generation_value_offset = generation_key_offset + 1;
        let classical_signature_offset = generation_value_offset + 1 + 3;
        let pq_entry_offset = classical_signature_offset + 64;
        let pq_signature_offset = pq_entry_offset + 4;
        assert_eq!(
            pq_signature_offset + pq_backend::SIGNATURE_BYTES,
            encoded.len(),
            "frozen wrapper field layout"
        );

        let downgrade_purpose = HybridPurpose::WalletExportV1.id();
        let mut downgrade_hex = vec![0x60 + u8::try_from(downgrade_purpose.len()).expect("short")];
        downgrade_hex.extend_from_slice(downgrade_purpose.as_bytes());
        let mutations = json!({
            "version": 1,
            "profile": PROFILE,
            "purpose": unsigned.purpose.id(),
            "credential_format": FORMAT,
            "tbs_vector": "hybrid-pq-v1-component-tbs.hex",
            "provenance": {
                "p256_private_scalar_hex": hex::encode([7_u8; 32]),
                "ml_dsa_65_keygen_seed_hex": hex::encode([0x42_u8; 32]),
                "ml_dsa_65_signing_randomness_hex": hex::encode([0x24_u8; 32]),
                "test_only": true
            },
            "binding": {
                "classical_key_id": unsigned.classical_kid.clone(),
                "pq_key_id": unsigned.pq_kid.clone(),
                "generation": unsigned.generation
            },
            "context": {
                "wallet_identity_hex": hex::encode(&unsigned.context.wallet_identity),
                "issuer_identity_hex": hex::encode(unsigned.context.issuer_identity.as_deref().expect("issuer identity")),
                "key_generation": unsigned.context.key_generation,
                "transaction_id_hex": hex::encode(unsigned.context.transaction_id.as_deref().expect("transaction")),
                "audience_hex": hex::encode(unsigned.context.audience.as_deref().expect("audience")),
                "nonce_hex": hex::encode(&unsigned.context.nonce),
                "created_at_epoch_seconds": unsigned.context.created_at_epoch_seconds,
                "expires_at_epoch_seconds": unsigned.context.expires_at_epoch_seconds
            },
            "mutations": [
                {"name":"bad-prefix", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":0, "value":1}]},
                {"name":"unsupported-version", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":version_offset, "value":3}]},
                {"name":"noncanonical-version", "target":"wrapper-envelope", "operations":[{"op":"replace", "offset":version_offset, "delete":1, "hex":"1801"}]},
                {"name":"unknown-profile", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":profile_offset + PROFILE.len() - 1, "value":3}]},
                {"name":"non-wrapper-purpose", "target":"wrapper-envelope", "operations":[{"op":"replace", "offset":purpose_offset - 1, "delete":unsigned.purpose.id().len() + 1, "hex":hex::encode(&downgrade_hex)}]},
                {"name":"unknown-purpose", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":purpose_offset + unsigned.purpose.id().len() - 1, "value":3}]},
                {"name":"unsupported-format", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":format_offset, "value":1}]},
                {"name":"changed-payload", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":payload_offset, "value":1}]},
                {"name":"changed-disclosure", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":first_disclosure_offset, "value":1}]},
                {"name":"reordered-disclosures", "target":"wrapper-envelope", "operations":[{"op":"replace", "offset":disclosure_region.start, "delete":disclosure_region.end - disclosure_region.start, "hex":hex::encode(&swapped_disclosures)}]},
                {"name":"changed-classical-kid", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":classical_kid_offset, "value":1}]},
                {"name":"changed-pq-kid", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":pq_kid_offset, "value":1}]},
                {"name":"zero-generation", "target":"wrapper-envelope", "operations":[{"op":"replace", "offset":generation_value_offset, "delete":1, "hex":"00"}]},
                {"name":"mixed-generation", "target":"wrapper-envelope", "operations":[{"op":"replace", "offset":generation_value_offset, "delete":1, "hex":"08"}]},
                {"name":"invalid-classical-signature", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":classical_signature_offset, "value":1}]},
                {"name":"invalid-pq-signature", "target":"wrapper-envelope", "operations":[{"op":"xor", "offset":pq_signature_offset, "value":1}]},
                {"name":"classical-only-downgrade", "target":"wrapper-envelope", "operations":[
                    {"op":"xor", "offset":magic_len, "value":1},
                    {"op":"remove", "offset":pq_entry_offset, "count":4 + pq_backend::SIGNATURE_BYTES}
                ]},
                {"name":"pq-only-downgrade", "target":"wrapper-envelope", "operations":[
                    {"op":"xor", "offset":magic_len, "value":1},
                    {"op":"remove", "offset":generation_value_offset + 1, "count":3 + 64}
                ]},
                {"name":"truncated", "target":"wrapper-envelope", "operations":[{"op":"truncate", "count":1}]},
                {"name":"trailing-cbor", "target":"wrapper-envelope", "operations":[{"op":"append", "hex":"00"}]},
                {"name":"appended-duplicate-field", "target":"wrapper-envelope", "operations":[
                    {"op":"xor", "offset":magic_len, "value":7},
                    {"op":"append", "hex":"0101"}
                ]}
            ]
        });
        assert_or_update_vector(
            "hybrid-pq-v1-wrapper-mutations.json",
            &serde_json::to_string_pretty(&mutations).expect("wrapper mutation JSON"),
        );

        let parameters = VerificationParameters {
            purpose: unsigned.purpose,
            context: &unsigned.context,
            classical_kid: &unsigned.classical_kid,
            pq_kid: &unsigned.pq_kid,
            classical_public_key: &classical_public_key,
            pq_public_key: &pq_public_key,
            generation: unsigned.generation,
        };
        verify(&encoded, &parameters).expect("shared wrapper vector verifies");

        let consumed: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(vector_path("hybrid-pq-v1-wrapper-mutations.json"))
                .expect("shared wrapper mutation corpus"),
        )
        .expect("valid wrapper mutation JSON");
        for mutation in consumed["mutations"].as_array().expect("mutation list") {
            assert_eq!(
                mutation["target"].as_str().expect("mutation target"),
                "wrapper-envelope"
            );
            let mutated = apply_vector_operations(
                encoded.clone(),
                mutation["operations"].as_array().expect("operations"),
            );
            assert!(
                verify(&mutated, &parameters).is_err(),
                "{} must reject",
                mutation["name"]
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn consumes_deterministic_real_signature_component_corpus() {
        let classical_key =
            SigningKey::from_bytes((&[7_u8; 32]).into()).expect("fixed vector P-256 key");
        let mut pq_key_pair = generate_key_pair([0x42; 32]);
        let unsigned = UnsignedEnvelope {
            purpose: HybridPurpose::TestSdJwtWrapperV1,
            context: issuer_context(9),
            payload: b"shared experimental credential payload".to_vec(),
            disclosures: vec![
                b"shared disclosure one".to_vec(),
                b"shared disclosure two".to_vec(),
            ],
            classical_kid: "shared-classical-kid-v1".into(),
            pq_kid: "shared-pq-kid-v1".into(),
            generation: 9,
        };
        let signed = tbs(&unsigned).expect("shared vector TBS");
        let classical_signature: Signature = classical_key.sign(&signed);
        let pq_signature = sign(&pq_key_pair.signing_key, &signed, &[], [0x24; 32])
            .expect("fixed-randomness ML-DSA vector")
            .as_slice()
            .to_vec();
        let classical_public_key = classical_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let pq_public_key = pq_key_pair.verification_key.as_slice().to_vec();
        let public_key_envelope = encode_public_key_envelope(&classical_public_key, &pq_public_key)
            .expect("shared public-key envelope");
        let signature_envelope = encode_signature_envelope(
            unsigned.purpose,
            &EnvelopeSignatures {
                classical: classical_signature.to_bytes().to_vec(),
                post_quantum: pq_signature,
            },
        )
        .expect("shared signature envelope");
        pq_key_pair.signing_key.as_mut_slice().zeroize();

        assert_or_update_vector("hybrid-pq-v1-component-tbs.hex", &hex::encode(&signed));
        assert_or_update_vector(
            "hybrid-pq-v1-public-key-envelope.hex",
            &hex::encode(&public_key_envelope),
        );
        assert_or_update_vector(
            "hybrid-pq-v1-signature-envelope.hex",
            &hex::encode(&signature_envelope),
        );

        let profile_offset = signature_envelope
            .windows(PROFILE.len())
            .position(|window| window == PROFILE.as_bytes())
            .expect("profile offset");
        let classical_signature_offset = profile_offset + PROFILE.len() + 3;
        let pq_signature_offset = classical_signature_offset + 64 + 4;
        let purpose_offset = pq_signature_offset + pq_backend::SIGNATURE_BYTES + 2;
        let mutations = json!({
            "version": 1,
            "profile": PROFILE,
            "purpose": unsigned.purpose.id(),
            "provenance": {
                "p256_private_scalar_hex": hex::encode([7_u8; 32]),
                "ml_dsa_65_keygen_seed_hex": hex::encode([0x42_u8; 32]),
                "ml_dsa_65_signing_randomness_hex": hex::encode([0x24_u8; 32]),
                "test_only": true
            },
            "mutations": [
                {"name":"bad-prefix", "target":"public-key-envelope", "operations":[{"op":"xor", "offset":0, "value":1}]},
                {"name":"unsupported-version", "target":"public-key-envelope", "operations":[{"op":"xor", "offset":ENVELOPE_MAGIC.len() + 2, "value":3}]},
                {"name":"unsupported-kind", "target":"public-key-envelope", "operations":[{"op":"xor", "offset":ENVELOPE_MAGIC.len() + 4, "value":3}]},
                {"name":"unknown-profile", "target":"signature-envelope", "operations":[{"op":"xor", "offset":profile_offset + PROFILE.len() - 1, "value":3}]},
                {"name":"invalid-classical-signature", "target":"signature-envelope", "operations":[{"op":"xor", "offset":classical_signature_offset, "value":1}]},
                {"name":"invalid-pq-signature", "target":"signature-envelope", "operations":[{"op":"xor", "offset":pq_signature_offset, "value":1}]},
                {"name":"unknown-purpose", "target":"signature-envelope", "operations":[{"op":"xor", "offset":purpose_offset + unsigned.purpose.id().len() - 1, "value":3}]},
                {"name":"truncated", "target":"signature-envelope", "operations":[{"op":"truncate", "count":1}]},
                {"name":"trailing-cbor", "target":"signature-envelope", "operations":[{"op":"append", "hex":"00"}]},
                {"name":"noncanonical-version", "target":"public-key-envelope", "operations":[{"op":"replace", "offset":ENVELOPE_MAGIC.len() + 1, "delete":1, "hex":"1801"}]},
                {"name":"missing-classical-component", "target":"signature-envelope", "operations":[
                    {"op":"xor", "offset":ENVELOPE_MAGIC.len(), "value":3},
                    {"op":"remove", "offset":classical_signature_offset - 3, "count":67}
                ]},
                {"name":"missing-pq-component", "target":"signature-envelope", "operations":[
                    {"op":"xor", "offset":ENVELOPE_MAGIC.len(), "value":3},
                    {"op":"remove", "offset":pq_signature_offset - 4, "count":pq_backend::SIGNATURE_BYTES + 4}
                ]}
            ]
        });
        assert_or_update_vector(
            "hybrid-pq-v1-component-mutations.json",
            &serde_json::to_string_pretty(&mutations).expect("mutation JSON"),
        );

        let consumed_mutations: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(vector_path("hybrid-pq-v1-component-mutations.json"))
                .expect("shared mutation corpus"),
        )
        .expect("valid shared mutation JSON");
        for mutation in consumed_mutations["mutations"]
            .as_array()
            .expect("mutation list")
        {
            let target = mutation["target"].as_str().expect("mutation target");
            let base = match target {
                "public-key-envelope" => public_key_envelope.clone(),
                "signature-envelope" => signature_envelope.clone(),
                _ => panic!("unknown mutation target"),
            };
            let mutated = apply_vector_operations(
                base,
                mutation["operations"].as_array().expect("operations"),
            );
            if target == "public-key-envelope" {
                assert!(
                    decode_public_key_envelope(&mutated).is_err(),
                    "{} must reject",
                    mutation["name"]
                );
                continue;
            }
            match decode_signature_envelope(&mutated, unsigned.purpose) {
                Err(_) => {}
                Ok(decoded) => {
                    let classical = Signature::from_slice(&decoded.classical)
                        .expect("fixed-size classical mutation");
                    let classical_valid = classical_key
                        .verifying_key()
                        .verify(&signed, &classical)
                        .is_ok();
                    let pq_valid = pq_backend::verify_signature(
                        &pq_public_key,
                        &signed,
                        &decoded.post_quantum,
                    )
                    .is_ok();
                    assert!(
                        !(classical_valid && pq_valid),
                        "{} must reject",
                        mutation["name"]
                    );
                }
            }
        }
    }
}
