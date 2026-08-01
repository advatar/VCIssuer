//! Cross-repository ActiveChain schema mapping for externally issued credentials.

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingError {
    InvalidInput,
}

fn update_length_prefixed(hasher: &mut Shake256, value: &[u8]) {
    hasher.update(&(value.len() as u32).to_be_bytes());
    hasher.update(value);
}

/// Mirrors ActiveChain P-096 exactly. The result is selected from a pinned table; it is never
/// accepted from an issuance or presentation request.
pub fn derive_schema_id(
    configuration: &[u8],
    credential_type: &[u8],
    rulebook_id: &[u8],
    rulebook_version: u32,
    rulebook_digest: [u8; 48],
) -> Result<[u8; 48], MappingError> {
    if [configuration, credential_type, rulebook_id]
        .into_iter()
        .any(|value| value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES)
        || rulebook_version == 0
        || rulebook_digest == [0; 48]
    {
        return Err(MappingError::InvalidInput);
    }
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-EUDI-SCHEMA-V1");
    update_length_prefixed(&mut hasher, configuration);
    update_length_prefixed(&mut hasher, credential_type);
    update_length_prefixed(&mut hasher, rulebook_id);
    hasher.update(&rulebook_version.to_be_bytes());
    update_length_prefixed(&mut hasher, &rulebook_digest);
    let mut output = [0; 48];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    Ok(output)
}

fn decode_digest(value: &str) -> Option<[u8; 48]> {
    if value.len() != 96 {
        return None;
    }
    let mut output = [0; 48];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

/// Closed runtime table for the seven non-hybrid configurations published by this issuer.
pub fn pinned_schema_id(configuration: &str) -> Option<[u8; 48]> {
    let (credential_type, rulebook_id, rulebook_digest) = match configuration {
        "eu.europa.ec.eudi.pid_vc_sd_jwt.de" => (
            "eu.europa.ec.eudi.pid.1",
            "dev.advatar.eudi.pid-sd-jwt-profile",
            "cdf11a6e5f93549443c33af2ea7cab2ffeca1d7bbd13338438113892cf28cf50d6f03389031edbbad18343979436f94e",
        ),
        "eu.europa.ec.eudi.pid_mso_mdoc.de" => (
            "eu.europa.ec.eudi.pid.1",
            "dev.advatar.eudi.pid-mdoc-profile",
            "42f7a85eb0aef0c9b5b515ceacdd9ab14f5302e8a8c737266e955f8489424ed2014bcb046013721f17c2439ae12ac22b",
        ),
        "org.iso.18013.5.1.mDL.de" => (
            "org.iso.18013.5.1.mDL",
            "dev.advatar.eudi.mdl-mdoc-profile",
            "3fa4eace7934699504bb655dd427f26060a282ad66d92fdab33c1a3c1b09ff35e64428ed1861d9bcbb17b1faf97d93b1",
        ),
        "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt:de" => (
            "urn:eu.europa.ec.eudi:learning:credential:1",
            "dev.advatar.eudi.learning-qeaa-profile",
            "d2df712931285cc51127794f1053b15eaec1ef55ccfebbe0e7c5e9cfd8bc8c62b1305c555b830ed4b2d5d96ec5ae0af0",
        ),
        "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt:de:pid-bound" => (
            "urn:eu.europa.ec.eudi:learning:credential:1",
            "dev.advatar.eudi.learning-qeaa-pid-bound-profile",
            "e588d0ec0b3ce34a46d644d8411047a7e1626c4912aa4129f0d2d928eae3af5b8a08defad57f1ec7d9d0bb2c35fbc49c",
        ),
        "dev.svipe.pid.sd-jwt" => (
            "dev.eu.europa.ec.eudi.pid.1",
            "dev.advatar.svipe-pid-development-profile",
            "1c1bf17a294402c20945962c79677a286ec2bbb0a0a740b302b94c7ecbf42a2984250df9cd5480bc295e8fb3dae09950",
        ),
        "dev.advatar.tlsn.evidence.sd-jwt" => (
            "dev.advatar.tlsn.evidence.1",
            "dev.advatar.tlsn-evidence-development-profile",
            "e13f89002120231a7975ad6fd42a07a98c7768e7b8caa8336ade7368effb1d897a512f864a10a5561a42ec9c7eb198c6",
        ),
        _ => return None,
    };
    derive_schema_id(
        configuration.as_bytes(),
        credential_type.as_bytes(),
        rulebook_id.as_bytes(),
        1,
        decode_digest(rulebook_digest)?,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex48(value: &str) -> [u8; 48] {
        assert_eq!(value.len(), 96);
        let mut output = [0; 48];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    #[test]
    fn consumes_the_shared_activechain_mapping_corpus() {
        let vector = include_str!("../tests/vectors/eudi-schema-mapping-v1.tsv");
        let mut lines = vector.lines();
        assert_eq!(
            lines.next(),
            Some(
                "credential_configuration_id\tcredential_type\trulebook_id\trulebook_version\trulebook_digest\tschema_id"
            )
        );
        let mut configurations = Vec::new();
        let mut schemas = Vec::new();
        for line in lines {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 6);
            let schema = derive_schema_id(
                fields[0].as_bytes(),
                fields[1].as_bytes(),
                fields[2].as_bytes(),
                fields[3].parse().unwrap(),
                hex48(fields[4]),
            )
            .unwrap();
            assert_eq!(schema, hex48(fields[5]));
            assert_eq!(pinned_schema_id(fields[0]), Some(schema));
            configurations.push(fields[0]);
            schemas.push(schema);
        }
        assert_eq!(configurations.len(), 7);
        configurations.sort_unstable();
        configurations.dedup();
        schemas.sort_unstable();
        schemas.dedup();
        assert_eq!(configurations.len(), 7);
        assert_eq!(schemas.len(), 7);
        assert_eq!(pinned_schema_id("unknown.profile"), None);
        for expected in [
            crate::PID_SD_JWT,
            crate::PID_MDOC,
            crate::EAA_MDOC,
            crate::QEAA_SD_JWT,
            crate::QEAA_PID_BOUND_SD_JWT,
            crate::DEV_SVIPE_PID_SD_JWT,
            crate::TLSN_EVIDENCE_SD_JWT,
        ] {
            assert!(
                configurations.binary_search(&expected).is_ok(),
                "missing mapping {expected}"
            );
        }
    }

    #[test]
    fn rejects_unbounded_zero_and_versionless_inputs() {
        assert_eq!(
            derive_schema_id(b"", b"type", b"rulebook", 1, [1; 48]),
            Err(MappingError::InvalidInput)
        );
        assert_eq!(
            derive_schema_id(b"config", b"type", b"rulebook", 0, [1; 48]),
            Err(MappingError::InvalidInput)
        );
        assert_eq!(
            derive_schema_id(b"config", b"type", b"rulebook", 1, [0; 48]),
            Err(MappingError::InvalidInput)
        );
        assert_eq!(
            derive_schema_id(&[b'a'; 257], b"type", b"rulebook", 1, [1; 48]),
            Err(MappingError::InvalidInput)
        );
    }

    #[test]
    fn published_metadata_uses_the_pinned_mapping_and_unknown_profiles_do_not() {
        let pid = crate::sd_jwt_profile(crate::PID_SD_JWT, crate::PID_VCT, "PID");
        assert_eq!(
            pid["activechain_schema_id_v1"],
            hex::encode(pinned_schema_id(crate::PID_SD_JWT).unwrap())
        );
        let mdoc = crate::mdoc_profile(crate::PID_MDOC, crate::PID_VCT, "PID mdoc");
        assert_eq!(
            mdoc["activechain_schema_id_v1"],
            hex::encode(pinned_schema_id(crate::PID_MDOC).unwrap())
        );
        let unknown = crate::sd_jwt_profile("unknown.profile", "unknown.type", "Unknown");
        assert!(unknown.get("activechain_schema_id_v1").is_none());
    }
}
