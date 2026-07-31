//! Provisional private `euwallet-hybrid-pq-v1` envelope.
//!
//! The field assignments and vectors remain an interoperability checkpoint:
//! they must be replaced or pinned when the shared `EUWallet` corpus lands.

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
const MAX_FIELD_BYTES: usize = 4_096;
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

pub fn encode(
    unsigned: &UnsignedEnvelope,
    signatures: &EnvelopeSignatures,
) -> Result<Vec<u8>, HybridCodecError> {
    if signatures.classical.len() != 64
        || signatures.post_quantum.len() != pq_backend::SIGNATURE_BYTES
    {
        return Err(HybridCodecError::Missing);
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
    let disclosures = byte_array(&fields[5].1)?;
    let classical_kid = text(&fields[6].1)?.to_owned();
    let pq_kid = text(&fields[7].1)?.to_owned();
    let generation = integer(&fields[8].1)?;
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
    use p256::ecdsa::{
        SigningKey,
        signature::{Signer, Verifier},
    };

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
}
