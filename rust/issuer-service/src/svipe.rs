//! Development-only Svipe identity evidence mapping.
//!
//! This module deliberately stops at a typed proofing record.  Svipe is not a
//! production PID trust anchor; the OIDC transport and issuer policy must mark
//! the resulting credential as development-only.

use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "dev.svipe.pid.sd-jwt";

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SvipeClaims {
    pub sub: String,
    pub given_name: String,
    pub family_name: String,
    pub birthdate: String,
    pub nationality: String,
    pub(crate) document_portrait: Option<String>,
    pub(crate) validation_portrait_present: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct DevIdentityEvidence {
    pub subject: String,
    pub given_name: String,
    pub family_name: String,
    pub birthdate: String,
    pub nationality: String,
    pub portrait: String,
    pub source: &'static str,
    pub development_only: bool,
}

#[allow(dead_code)]
pub fn normalize(claims: SvipeClaims) -> Result<DevIdentityEvidence, &'static str> {
    for value in [
        &claims.sub,
        &claims.given_name,
        &claims.family_name,
        &claims.birthdate,
        &claims.nationality,
    ] {
        if value.trim().is_empty() || value.len() > 512 {
            return Err("required Svipe identity claim is missing or oversized");
        }
    }
    let portrait = claims
        .document_portrait
        .filter(|v| !v.trim().is_empty())
        .ok_or("Svipe development proof has no document portrait")?;
    if claims.validation_portrait_present != Some(true) {
        return Err("Svipe portrait-presence validation is required");
    }
    Ok(DevIdentityEvidence {
        subject: claims.sub,
        given_name: claims.given_name,
        family_name: claims.family_name,
        birthdate: claims.birthdate,
        nationality: claims.nationality,
        portrait,
        source: "svipe_oidc",
        development_only: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claims() -> SvipeClaims {
        SvipeClaims {
            sub: "s".into(),
            given_name: "Ada".into(),
            family_name: "Lovelace".into(),
            birthdate: "1815-12-10".into(),
            nationality: "GB".into(),
            document_portrait: Some("data:image/jpeg;base64,AA==".into()),
            validation_portrait_present: Some(true),
        }
    }
    #[test]
    fn maps_only_development_evidence() {
        let e = normalize(claims()).unwrap();
        assert!(e.development_only);
        assert_eq!(e.source, "svipe_oidc");
    }
    #[test]
    fn portrait_is_required() {
        let mut c = claims();
        c.document_portrait = None;
        assert!(normalize(c).is_err());
    }
}
