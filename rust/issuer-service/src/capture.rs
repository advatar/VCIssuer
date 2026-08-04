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
    pub expires_at: u64,
}

/// Request to open a capture session: the target wallet presents its proof-of-possession public key
/// (an EC P-256 JWK, parsed and validated by the handler).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCaptureSessionRequest {
    pub holder_jwk: Value,
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
/// (App Clip on iOS) for this session. `origin` is the issuer origin (scheme + host), no trailing
/// slash.
#[must_use]
pub fn invocation_url(origin: &str, session_id: &str) -> String {
    format!(
        "{}/pid-capture?session={session_id}",
        origin.trim_end_matches('/')
    )
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
