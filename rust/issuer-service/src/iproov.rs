//! iProov Service Provider client for Genuine Presence Assurance (GPA) liveness.
//!
//! `VCIssuer` is the Service Provider: it mints a per-session verify token (the wallet/capture SDK
//! launches with it — the SAME `MANDAMUS_IPROOV_*` SP credentials drive the iOS SDK and the Web SDK),
//! and it validates the completed capture server-to-server. The validated verdict is the
//! **authoritative** `liveness_matched` fed into the Lean-proved NFC-PID gate — the issuer proves
//! liveness itself rather than trusting a reader attestation.
//!
//! Credentials and the regional base come from the environment, matching the Mandamus/WAUTH
//! convention so operators provision the SP once:
//!
//! * `MANDAMUS_IPROOV_BASE_URL` — e.g. `https://eu.rp.secure.iproov.me/api/v2` (scheme + `/api/v2`)
//! * `MANDAMUS_IPROOV_API_KEY`
//! * `MANDAMUS_IPROOV_SECRET`
//! * `MANDAMUS_IPROOV_ASSURANCE_TYPE` — optional, defaults to `genuine_presence` (GPA); set
//!   `liveness` only for accounts provisioned for Liveness Assurance
//! * `MANDAMUS_IPROOV_WEB_BASE_URL` — optional streaming URL (e.g. `wss://…/ws`); derived from the
//!   base host when unset
//!
//! Any of the three required vars unset ⇒ [`IProovConfig::from_env`] returns `None`, the iProov-gated
//! flow is disabled, and NFC-PID capture **fails closed**. Secrets are never hard-coded or logged.
//!
//! The wire contract follows the iProov Claim API v2 (`{base}/claim/verify/{token,validate}`) exactly
//! as the WAUTH doorkeeper core uses it. Request builders and response parsers are split out as pure
//! functions and unit-tested; the async wrappers are wired by the capture-session backend.

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// GPA assurance level (vs. the weaker `liveness`).
pub const ASSURANCE_GENUINE_PRESENCE: &str = "genuine_presence";
/// Client label sent to iProov for this integration.
pub const CLIENT_ID: &str = "eudi-wallet-pid-capture";

/// Trusted iProov Service Provider configuration, loaded from the environment.
#[derive(Clone)]
pub struct IProovConfig {
    api_key: String,
    secret: String,
    /// Regional API base including scheme and `/api/v2`, trailing slash stripped
    /// (e.g. `https://eu.rp.secure.iproov.me/api/v2`).
    base_url: String,
    /// `genuine_presence` (GPA) or `liveness` (LA); the level tokens are minted at AND the level a
    /// validate response must confirm (downgrade-closed).
    assurance_type: String,
    /// Optional client-safe streaming URL for the capture SDK; derived from `base_url` when absent.
    web_base_url: Option<String>,
}

/// Extract the bare host from a base URL (`https://host/api/v2` → `host`).
fn host_of(base_url: &str) -> &str {
    let no_scheme = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .unwrap_or(base_url);
    no_scheme.split('/').next().unwrap_or(no_scheme)
}

/// iProov user ids must be clean identifiers — a DID like `did:ex:alice` (colons) is rejected as
/// "Invalid User ID". Map anything outside the safe charset to a STABLE SHA-256 hex digest so the
/// same principal always yields the same iProov user id (token and validate must agree).
#[must_use]
pub fn safe_user_id(raw: &str) -> String {
    let safe = !raw.is_empty()
        && raw.len() <= 255
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'-'));
    if safe {
        raw.to_owned()
    } else {
        hex::encode(Sha256::digest(raw.as_bytes()))
    }
}

impl IProovConfig {
    /// Load from the environment. Returns `None` if any required field is unset/empty — the caller
    /// then disables the iProov-gated flow (fail-closed), never a partial configuration.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("MANDAMUS_IPROOV_BASE_URL")
            .ok()
            .filter(|v| !v.is_empty())?
            .trim_end_matches('/')
            .to_owned();
        let api_key = std::env::var("MANDAMUS_IPROOV_API_KEY")
            .ok()
            .filter(|v| !v.is_empty())?;
        let secret = std::env::var("MANDAMUS_IPROOV_SECRET")
            .ok()
            .filter(|v| !v.is_empty())?;
        let assurance_type = std::env::var("MANDAMUS_IPROOV_ASSURANCE_TYPE")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| ASSURANCE_GENUINE_PRESENCE.to_owned());
        let web_base_url = std::env::var("MANDAMUS_IPROOV_WEB_BASE_URL")
            .ok()
            .filter(|v| !v.is_empty());
        Some(Self {
            api_key,
            secret,
            base_url,
            assurance_type,
            web_base_url,
        })
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            api_key: "test-api-key".into(),
            secret: "test-secret".into(),
            base_url: "https://eu.rp.secure.iproov.me/api/v2".into(),
            assurance_type: ASSURANCE_GENUINE_PRESENCE.into(),
            web_base_url: None,
        }
    }

    /// The assurance level tokens are minted at and validate responses must confirm.
    #[must_use]
    pub fn assurance_type(&self) -> &str {
        &self.assurance_type
    }

    #[must_use]
    pub fn token_endpoint(&self) -> String {
        format!("{}/claim/verify/token", self.base_url)
    }

    #[must_use]
    pub fn validate_endpoint(&self) -> String {
        format!("{}/claim/verify/validate", self.base_url)
    }

    /// The streaming URL the capture SDK connects to (`IProov.launch(streamingURL:)` on iOS, the
    /// `<iproov-me>` component on the web). Client-safe (not a secret).
    #[must_use]
    pub fn streaming_url(&self) -> String {
        match &self.web_base_url {
            Some(w) if !w.is_empty() => w.clone(),
            _ => format!("wss://{}/ws", host_of(&self.base_url)),
        }
    }
}

/// Body for `claim/verify/token`. `user_id` is an opaque per-session subject (never real identity);
/// `resource` names what the liveness authorises (the PID capture session).
#[must_use]
pub fn token_request_body(cfg: &IProovConfig, user_id: &str, resource: &str) -> Value {
    json!({
        "api_key": cfg.api_key,
        "secret": cfg.secret,
        "resource": resource,
        "client": CLIENT_ID,
        "assurance_type": cfg.assurance_type,
        "user_id": user_id,
    })
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

/// Extract the token from a `claim/verify/token` response.
pub fn parse_token_response(body: &str) -> Result<String, String> {
    let parsed: TokenResponse =
        serde_json::from_str(body).map_err(|e| format!("iproov token response: {e}"))?;
    if parsed.token.is_empty() {
        return Err("iproov token response carried an empty token".into());
    }
    Ok(parsed.token)
}

/// Body for `claim/verify/validate`. `token` is the one minted for this session; `user_id` must
/// match the value used at token creation.
#[must_use]
pub fn validate_request_body(
    cfg: &IProovConfig,
    token: &str,
    user_id: &str,
    client_ip: &str,
) -> Value {
    json!({
        "api_key": cfg.api_key,
        "secret": cfg.secret,
        "token": token,
        "client": CLIENT_ID,
        "user_id": user_id,
        "ip": client_ip,
    })
}

#[derive(Deserialize)]
struct ValidateResponse {
    #[serde(default)]
    passed: bool,
    #[serde(default)]
    assurance_type: Option<String>,
}

/// Reduce a `claim/verify/validate` response to the authoritative liveness verdict, **downgrade-
/// closed**: the capture must have `passed` AND the response must explicitly confirm the required
/// assurance level. A pass at a weaker level (`liveness` when GPA is required) — or an absent
/// `assurance_type`, which is not evidence the level was achieved — is treated as a failure. A
/// genuinely failed capture is a `200` with `passed:false`; a malformed request is surfaced as an
/// HTTP error by the async wrapper before this is reached.
pub fn parse_validate_response(body: &str, required_assurance: &str) -> Result<bool, String> {
    let parsed: ValidateResponse =
        serde_json::from_str(body).map_err(|e| format!("iproov validate response: {e}"))?;
    let assurance_ok = parsed
        .assurance_type
        .as_deref()
        .is_some_and(|a| a == required_assurance);
    Ok(parsed.passed && assurance_ok)
}

/// Mint a GPA verify token for a capture session (server-to-server). `user_id` is sanitised to a
/// clean iProov identifier; the caller MUST reuse the same raw `user_id` at validate time.
pub async fn create_token(
    client: &reqwest::Client,
    cfg: &IProovConfig,
    user_id: &str,
    resource: &str,
) -> Result<String, String> {
    let uid = safe_user_id(user_id);
    let response = client
        .post(cfg.token_endpoint())
        .json(&token_request_body(cfg, &uid, resource))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    parse_token_response(&response)
}

/// Validate a completed capture → the authoritative, downgrade-closed `liveness_matched` verdict.
pub async fn validate(
    client: &reqwest::Client,
    cfg: &IProovConfig,
    token: &str,
    user_id: &str,
    client_ip: &str,
) -> Result<bool, String> {
    let uid = safe_user_id(user_id);
    let response = client
        .post(cfg.validate_endpoint())
        .json(&validate_request_body(cfg, token, &uid, client_ip))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    parse_validate_response(&response, cfg.assurance_type())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_and_streaming_url_from_base() {
        let cfg = IProovConfig::for_test();
        assert_eq!(
            cfg.token_endpoint(),
            "https://eu.rp.secure.iproov.me/api/v2/claim/verify/token"
        );
        assert_eq!(
            cfg.validate_endpoint(),
            "https://eu.rp.secure.iproov.me/api/v2/claim/verify/validate"
        );
        // No explicit web base ⇒ derive wss from the API host.
        assert_eq!(cfg.streaming_url(), "wss://eu.rp.secure.iproov.me/ws");
    }

    #[test]
    fn explicit_web_base_wins_for_streaming() {
        let mut cfg = IProovConfig::for_test();
        cfg.web_base_url = Some("wss://eu.rp.secure.iproov.me/ws".into());
        assert_eq!(cfg.streaming_url(), "wss://eu.rp.secure.iproov.me/ws");
    }

    #[test]
    fn token_body_carries_sp_key_and_assurance() {
        let cfg = IProovConfig::for_test();
        let body = token_request_body(&cfg, "session-user-1", "pid-capture:sess-abc");
        assert_eq!(body["api_key"], "test-api-key");
        assert_eq!(body["secret"], "test-secret");
        assert_eq!(body["assurance_type"], ASSURANCE_GENUINE_PRESENCE);
        assert_eq!(body["user_id"], "session-user-1");
        assert_eq!(body["resource"], "pid-capture:sess-abc");
        assert_eq!(body["client"], CLIENT_ID);
    }

    #[test]
    fn validate_body_binds_token_and_user() {
        let cfg = IProovConfig::for_test();
        let body = validate_request_body(&cfg, "tok-xyz", "session-user-1", "203.0.113.7");
        assert_eq!(body["token"], "tok-xyz");
        assert_eq!(body["user_id"], "session-user-1");
        assert_eq!(body["ip"], "203.0.113.7");
        assert_eq!(body["secret"], "test-secret");
    }

    #[test]
    fn parses_token_and_rejects_empty() {
        assert_eq!(
            parse_token_response(r#"{"token":"abc.def"}"#).unwrap(),
            "abc.def"
        );
        assert!(parse_token_response(r#"{"token":""}"#).is_err());
        assert!(parse_token_response(r#"{"nope":1}"#).is_err());
        assert!(parse_token_response("not json").is_err());
    }

    #[test]
    fn validate_is_downgrade_closed() {
        let gpa = ASSURANCE_GENUINE_PRESENCE;
        // Passed AND assurance confirms the required level.
        assert!(
            parse_validate_response(
                r#"{"passed":true,"assurance_type":"genuine_presence"}"#,
                gpa
            )
            .unwrap()
        );
        // Passed but at a WEAKER level ⇒ rejected.
        assert!(
            !parse_validate_response(r#"{"passed":true,"assurance_type":"liveness"}"#, gpa)
                .unwrap()
        );
        // Passed but assurance ABSENT ⇒ not evidence the level was achieved ⇒ rejected.
        assert!(!parse_validate_response(r#"{"passed":true}"#, gpa).unwrap());
        // Genuine capture failure.
        assert!(
            !parse_validate_response(
                r#"{"passed":false,"assurance_type":"genuine_presence","reason":"user_timeout"}"#,
                gpa
            )
            .unwrap()
        );
        // Missing everything ⇒ fail-closed.
        assert!(!parse_validate_response(r#"{"other":1}"#, gpa).unwrap());
        assert!(parse_validate_response("not json", gpa).is_err());
    }

    #[test]
    fn safe_user_id_passes_clean_and_hashes_dirty() {
        assert_eq!(safe_user_id("session-user_1@a.b"), "session-user_1@a.b");
        // A DID with colons is not a clean iProov id ⇒ stable hash.
        let hashed = safe_user_id("did:ex:alice");
        assert_eq!(hashed.len(), 64);
        assert!(hashed.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(hashed, safe_user_id("did:ex:alice"));
        assert_ne!(hashed, safe_user_id("did:ex:bob"));
    }
}
