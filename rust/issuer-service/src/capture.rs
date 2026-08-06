//! Cross-wallet PID capture sessions.
//!
//! A *capture session* lets a standalone PID Capture companion (a separate iOS app / App Clip that
//! only reads the eMRTD chip over NFC and runs an iProov liveness capture) produce a PID for a
//! **different** wallet. `VCIssuer` generates a session bound to the target wallet's proof-of-
//! possession key, hands the companion an iProov verify token, and — once the companion returns the
//! chip attestation — validates liveness itself (authoritative) and issues the PID bound to that
//! target key. The companion never holds the credential and never sees a signing key.
//!
//! This module owns the session data model, the request/response DTOs, and the pure invocation-URL
//! and Apple-App-Site-Association builders. The orchestration handlers live in `main.rs` because
//! they reuse the (Lean-proved) kernel gate, the eMRTD attestation verifier, and the SD-JWT signer.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

/// How long a capture session accepts evidence before it must be recreated.
pub const CAPTURE_SESSION_TTL_SECONDS: u64 = 900;

/// Lifecycle of a capture session. Serialised into the poll response the target wallet reads.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    /// Created and waiting for the companion to submit chip + liveness evidence.
    AwaitingEvidence,
    /// Evidence verified and a PID minted and bound to the target wallet key.
    Issued,
    /// Evidence was rejected (chip, liveness, binding, or gate). Terminal.
    Failed,
}

/// A capture session bound to one target wallet key. Held in volatile state; never persisted with
/// the credential beyond the TTL.
pub struct CaptureSession {
    /// JWK thumbprint of the target wallet's proof-of-possession key — the PID is bound to this.
    pub holder_jkt: String,
    /// The target wallet's public JWK (`cnf` of the issued credential).
    pub holder_jwk: Value,
    /// Per-session nonce welded into the eMRTD attestation (replay + session binding).
    pub nonce: String,
    /// Opaque iProov user id for this session (never a real identity).
    pub iproov_user_id: String,
    /// The iProov verify token minted for the companion's capture, if the SP is configured.
    pub iproov_token: Option<String>,
    pub status: CaptureStatus,
    /// The issued PID SD-JWT, once `status == Issued`.
    pub credential: Option<String>,
    /// The issued PID mdoc (`mso_mdoc`, doctype `eu.europa.ec.eudi.pid.1`), once `status == Issued`.
    /// The ARF-required second format of the same captured PID, minted alongside the SD-JWT so the
    /// captured PID is presentable in person (ISO 18013-5) and over the Digital Credentials API.
    pub credential_mdoc: Option<String>,
    pub expires_at: u64,
    /// Optional APNs device token to notify when the PID is issued.
    pub device_token: Option<String>,
}

/// Request to open a capture session: the target wallet presents its proof-of-possession public key
/// (an EC P-256 JWK, parsed and validated by the handler).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCaptureSessionRequest {
    pub holder_jwk: Value,
    /// Optional APNs device token to notify when this session's PID is issued.
    #[serde(default)]
    pub device_token: Option<String>,
}

/// Response: what the target wallet displays as a QR (the companion invocation URL) plus the iProov
/// launch parameters the companion needs. Secrets (the SP api-key/secret) never appear here.
#[derive(Serialize)]
pub struct CreateCaptureSessionResponse {
    pub session_id: String,
    pub nonce: String,
    /// HTTPS App Clip / universal-link URL that launches the companion for this session.
    pub invocation_url: String,
    pub iproov_token: Option<String>,
    pub iproov_streaming_url: Option<String>,
    pub iproov_assurance_type: Option<String>,
    pub expires_in: u64,
}

/// Evidence the companion returns: the trusted-reader eMRTD attestation (compact JWS) and the client
/// IP for the iProov validate call. The iProov token is the one `VCIssuer` minted for the session,
/// so it is not resupplied here.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEvidenceRequest {
    pub attestation: String,
    #[serde(default)]
    pub client_ip: Option<String>,
}

/// The opaque iProov user id for a session — a clean identifier (the session id is already UUID-safe).
#[must_use]
pub fn iproov_user_id(session_id: &str) -> String {
    format!("pid-capture-{session_id}")
}

/// The iProov `resource` a capture authorises (audit + scoping).
#[must_use]
pub fn iproov_resource(session_id: &str) -> String {
    format!("pid-capture:{session_id}")
}

/// The HTTPS invocation URL a target wallet renders as a QR; scanning it launches the companion
/// (App Clip on iOS) for this session. `origin` is the PID-capture invocation origin (scheme +
/// host) — see [`invocation_origin`], which may differ from the issuer's own origin. A trailing
/// slash is trimmed.
#[must_use]
pub fn invocation_url(origin: &str, session_id: &str) -> String {
    format!(
        "{}/pid-capture?session={session_id}",
        origin.trim_end_matches('/')
    )
}

/// Resolve the origin used to build the companion invocation URL. The PID-capture invocation origin
/// can legitimately differ from the issuer's own origin — e.g. a dedicated host that serves the
/// Apple App Site Association and proxies the capture API, so the universal link opens the companion
/// app — so it is configured independently (`PID_CAPTURE_INVOCATION_ORIGIN`) and falls back to
/// `issuer_origin` when unset or blank. Whitespace and a trailing slash are trimmed.
#[must_use]
pub fn invocation_origin(configured: Option<String>, issuer_origin: &str) -> String {
    configured
        .map(|origin| origin.trim().trim_end_matches('/').to_owned())
        .filter(|origin| !origin.is_empty())
        .unwrap_or_else(|| issuer_origin.trim_end_matches('/').to_owned())
}

/// Build the `OpenID4VCI` credential offer for a freshly-issued PID, returning BOTH:
/// - the offer object, returned in-band so a target wallet polling `GET /v1/pid-capture/{id}`
///   (the cross-device path) can ingest it; and
/// - an `openid-credential-offer://` by-value deep link, so the companion can hand the PID off to a
///   wallet on the SAME device (a "final redirect"), or a wallet can open it directly.
///
/// The offer is carried by value (no `credential_offer_uri` round-trip) so it works offline and
/// cross-app without an extra fetch. `issuer_origin` must have no trailing slash.
///
/// `credentials` is one or more `(configuration_id, format, credential)` entries — the ARF
/// dual-format PID lists both the `dc+sd-jwt` and the `mso_mdoc` halves so a wallet ingests both
/// from a single offer.
#[must_use]
pub fn credential_offer(
    issuer_origin: &str,
    credentials: &[(&str, &str, &str)],
) -> (Value, String) {
    let configuration_ids: Vec<&str> = credentials.iter().map(|(id, _, _)| *id).collect();
    let credential_entries: Vec<Value> = credentials
        .iter()
        .map(|(_, format, credential)| json!({ "format": format, "credential": credential }))
        .collect();
    let offer = json!({
        "credential_issuer": issuer_origin,
        "credential_configuration_ids": configuration_ids,
        "credentials": credential_entries,
    });
    let mut link = Url::parse("openid-credential-offer://").expect("static scheme is valid");
    link.query_pairs_mut().append_pair(
        "credential_offer",
        &serde_json::to_string(&offer).expect("offer object serialises"),
    );
    (offer, link.to_string())
}

/// Build the `apple-app-site-association` document that lets the companion App Clip (and full app)
/// be invoked from the issuer domain. `app_id` is `TEAMID.bundle-id`; the App Clip id is
/// `{app_id}.Clip` by Apple convention.
#[must_use]
pub fn apple_app_site_association(app_id: &str) -> Value {
    let clip_id = format!("{app_id}.Clip");
    json!({
        "applinks": {
            "apps": [],
            "details": [{
                "appIDs": [app_id],
                "components": [{ "/": "/pid-capture*", "comment": "PID capture companion" }]
            }]
        },
        "appclips": {
            "apps": [clip_id]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_url_carries_session() {
        assert_eq!(
            invocation_url("https://issuer.advatar.systems/", "sess-123"),
            "https://issuer.advatar.systems/pid-capture?session=sess-123"
        );
    }

    #[test]
    fn invocation_origin_prefers_configured_then_issuer() {
        // A configured origin wins and is trimmed of a trailing slash.
        assert_eq!(
            invocation_origin(
                Some("https://pid.advatar.systems/".to_owned()),
                "https://issuer.advatar.systems"
            ),
            "https://pid.advatar.systems"
        );
        // Unset falls back to the issuer origin (also trimmed).
        assert_eq!(
            invocation_origin(None, "https://issuer.advatar.systems/"),
            "https://issuer.advatar.systems"
        );
        // A blank/whitespace configured value is ignored, so a stray empty env cannot break links.
        assert_eq!(
            invocation_origin(Some("   ".to_owned()), "https://issuer.advatar.systems"),
            "https://issuer.advatar.systems"
        );
    }

    #[test]
    fn iproov_ids_are_session_scoped() {
        assert_eq!(iproov_user_id("abc"), "pid-capture-abc");
        assert_eq!(iproov_resource("abc"), "pid-capture:abc");
    }

    #[test]
    fn aasa_declares_appclip_and_applink() {
        let aasa = apple_app_site_association("ABCDE12345.systems.advatar.pidcapture");
        assert_eq!(
            aasa["appclips"]["apps"][0],
            "ABCDE12345.systems.advatar.pidcapture.Clip"
        );
        assert_eq!(
            aasa["applinks"]["details"][0]["appIDs"][0],
            "ABCDE12345.systems.advatar.pidcapture"
        );
        assert_eq!(
            aasa["applinks"]["details"][0]["components"][0]["/"],
            "/pid-capture*"
        );
    }

    #[test]
    fn credential_offer_yields_object_and_by_value_deep_link() {
        let (offer, link) = credential_offer(
            "https://issuer.advatar.systems",
            &[(
                "eu.europa.ec.eudi.pid_vc_sd_jwt.de:nfc",
                "dc+sd-jwt",
                "eyJ.sd-jwt.credential~",
            )],
        );
        assert_eq!(offer["credential_issuer"], "https://issuer.advatar.systems");
        assert_eq!(
            offer["credential_configuration_ids"][0],
            "eu.europa.ec.eudi.pid_vc_sd_jwt.de:nfc"
        );
        // The deep link is a by-value openid-credential-offer:// URI whose `credential_offer` query
        // parameter round-trips back to the exact offer object the wallet must ingest.
        assert!(link.starts_with("openid-credential-offer://?credential_offer="));
        let parsed = Url::parse(&link).unwrap();
        let carried = parsed
            .query_pairs()
            .find(|(k, _)| k == "credential_offer")
            .map(|(_, v)| v.into_owned())
            .expect("credential_offer query present");
        assert_eq!(serde_json::from_str::<Value>(&carried).unwrap(), offer);
    }

    #[test]
    fn credential_offer_carries_both_arf_formats() {
        let (offer, _link) = credential_offer(
            "https://issuer.advatar.systems",
            &[
                (
                    "eu.europa.ec.eudi.pid_vc_sd_jwt.de:nfc",
                    "dc+sd-jwt",
                    "eyJ.sd-jwt~",
                ),
                (
                    "eu.europa.ec.eudi.pid_mso_mdoc.de:nfc",
                    "mso_mdoc",
                    "b64url-mdoc",
                ),
            ],
        );
        // Both configuration ids and both credential entries are listed, in order.
        assert_eq!(
            offer["credential_configuration_ids"],
            json!([
                "eu.europa.ec.eudi.pid_vc_sd_jwt.de:nfc",
                "eu.europa.ec.eudi.pid_mso_mdoc.de:nfc"
            ])
        );
        assert_eq!(offer["credentials"][0]["format"], "dc+sd-jwt");
        assert_eq!(offer["credentials"][1]["format"], "mso_mdoc");
        assert_eq!(offer["credentials"][1]["credential"], "b64url-mdoc");
    }

    #[test]
    fn status_serialises_snake_case() {
        assert_eq!(
            serde_json::to_string(&CaptureStatus::AwaitingEvidence).unwrap(),
            "\"awaiting_evidence\""
        );
        assert_eq!(
            serde_json::to_string(&CaptureStatus::Issued).unwrap(),
            "\"issued\""
        );
    }
}
