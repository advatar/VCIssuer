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
pub const PURPOSE: &str = "experimental-sd-jwt-wrapper";
pub const FORMAT: &str = "dev-hybrid-pq+cbor";
const DOMAIN: &[u8] = b"EUWALLET-HYBRID-SIGNATURE-V1";
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_PAYLOAD_BYTES: usize = 32 * 1024;
const MAX_CONTEXT_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct UnsignedEnvelope {
    pub context: Vec<u8>,
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

pub fn tbs(unsigned: &UnsignedEnvelope) -> Result<Vec<u8>, HybridCodecError> {
    if unsigned.context.len() > MAX_CONTEXT_BYTES || unsigned.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(HybridCodecError::Oversized);
    }
    let committed_payload = committed_payload(unsigned)?;
    let mut output = Vec::with_capacity(
        DOMAIN.len()
            + PROFILE.len()
            + PURPOSE.len()
            + unsigned.context.len()
            + committed_payload.len()
            + 16,
    );
    output.extend_from_slice(DOMAIN);
    append_component(&mut output, PROFILE.as_bytes())?;
    append_component(&mut output, PURPOSE.as_bytes())?;
    append_component(&mut output, &unsigned.context)?;
    append_component(&mut output, &committed_payload)?;
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
        pair(3, Value::Text(PURPOSE.into())),
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
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).map_err(|_| HybridCodecError::Malformed)?;
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(HybridCodecError::Oversized);
    }
    Ok(encoded)
}

#[allow(dead_code)]
pub fn verify(
    encoded: &[u8],
    context: &[u8],
    classical_public_key: &[u8],
    pq_public_key: &[u8],
    expected_generation: u64,
) -> Result<(), HybridCodecError> {
    let (unsigned, signatures) = decode(encoded, context)?;
    if unsigned.generation != expected_generation {
        return Err(HybridCodecError::GenerationMismatch);
    }
    let signed = tbs(&unsigned)?;
    let classical_key = VerifyingKey::from_sec1_bytes(classical_public_key)
        .map_err(|_| HybridCodecError::ClassicalSignature)?;
    let classical_signature = Signature::from_slice(&signatures.classical)
        .map_err(|_| HybridCodecError::ClassicalSignature)?;
    classical_key
        .verify(&signed, &classical_signature)
        .map_err(|_| HybridCodecError::ClassicalSignature)?;
    pq_backend::verify_signature(pq_public_key, &signed, &signatures.post_quantum)
        .map_err(|_| HybridCodecError::PostQuantumSignature)
}

fn decode(
    encoded: &[u8],
    context: &[u8],
) -> Result<(UnsignedEnvelope, EnvelopeSignatures), HybridCodecError> {
    if encoded.len() > MAX_ENVELOPE_BYTES || context.len() > MAX_CONTEXT_BYTES {
        return Err(HybridCodecError::Oversized);
    }
    let mut cursor = Cursor::new(encoded);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| HybridCodecError::Malformed)?;
    if usize::try_from(cursor.position()).ok() != Some(encoded.len()) {
        return Err(HybridCodecError::NonCanonical);
    }
    let mut canonical = Vec::new();
    ciborium::ser::into_writer(&value, &mut canonical).map_err(|_| HybridCodecError::Malformed)?;
    if canonical != encoded {
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
    let purpose = text(&fields[2].1)?;
    let format = text(&fields[3].1)?;
    if version != VERSION || profile != PROFILE || purpose != PURPOSE || format != FORMAT {
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
            context: context.to_vec(),
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

    fn fixture() -> Fixture {
        let classical_key =
            SigningKey::from_bytes((&[7_u8; 32]).into()).expect("fixed P-256 test key");
        let pq = pq_backend::generate().expect("system CSPRNG");
        let unsigned = UnsignedEnvelope {
            context: b"canonical audience, nonce, and generation context".to_vec(),
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
        let Value::Map(mut entries) = ciborium::de::from_reader(encoded).expect("fixture envelope")
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
        let mut result = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut result).expect("mutated envelope");
        result
    }

    fn verify_fixture(fixture: &Fixture, encoded: &[u8], context: &[u8], generation: u64) {
        verify(
            encoded,
            context,
            &fixture.classical_public_key,
            &fixture.pq_public_key,
            generation,
        )
        .expect("both signatures valid");
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
                verify(
                    &invalid,
                    &fixture.unsigned.context,
                    &fixture.classical_public_key,
                    &fixture.pq_public_key,
                    fixture.unsigned.generation,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn missing_or_unsupported_components_fail_closed() {
        let fixture = fixture();
        let Value::Map(mut entries) =
            ciborium::de::from_reader(fixture.encoded.as_slice()).expect("fixture envelope")
        else {
            panic!("fixture is a map");
        };
        entries.pop();
        let mut missing = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut missing).expect("missing field");
        assert!(decode(&missing, &fixture.unsigned.context).is_err());

        for (field, value) in [
            (1, Value::Integer(Integer::from(2_u64))),
            (2, Value::Text("unknown-profile".into())),
            (3, Value::Text("production-sd-jwt".into())),
        ] {
            assert!(
                decode(
                    &mutate_field(&fixture.encoded, field, value),
                    &fixture.unsigned.context
                )
                .is_err()
            );
        }
        assert!(decode(b"header.payload.signature", &fixture.unsigned.context).is_err());
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
                verify(
                    encoded,
                    &fixture.unsigned.context,
                    &fixture.classical_public_key,
                    &fixture.pq_public_key,
                    fixture.unsigned.generation,
                )
                .is_err()
            );
        }
        assert!(
            verify(
                &fixture.encoded,
                b"changed audience or nonce",
                &fixture.classical_public_key,
                &fixture.pq_public_key,
                fixture.unsigned.generation,
            )
            .is_err()
        );
        assert_eq!(
            verify(
                &fixture.encoded,
                &fixture.unsigned.context,
                &fixture.classical_public_key,
                &fixture.pq_public_key,
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
            decode(&trailing, &fixture.unsigned.context),
            Err(HybridCodecError::NonCanonical)
        ));

        let Value::Map(mut entries) =
            ciborium::de::from_reader(fixture.encoded.as_slice()).expect("fixture envelope")
        else {
            panic!("fixture is a map");
        };
        entries.push(entries[0].clone());
        let mut duplicate = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut duplicate).expect("duplicate map");
        assert!(matches!(
            decode(&duplicate, &fixture.unsigned.context),
            Err(HybridCodecError::DuplicateField)
        ));

        assert!(matches!(
            decode(
                &vec![0_u8; MAX_ENVELOPE_BYTES + 1],
                &fixture.unsigned.context
            ),
            Err(HybridCodecError::Oversized)
        ));
        assert!(decode(&[0xbf, 0xff], &fixture.unsigned.context).is_err());
    }
}
