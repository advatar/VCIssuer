//! iProov Service Provider client for Genuine Presence Assurance (GPA) liveness.
//!
//! `VCIssuer` is the Service Provider: it mints a per-session verify token (the wallet/capture SDK
//! launches with it) and validates the capture server-to-server. The validated verdict is the
//! **authoritative** `liveness_matched` fed into the Lean-proved NFC-PID gate — the issuer proves
//! liveness itself rather than trusting the reader attestation.
//!
//! Credentials come from the environment (`IPROOV_API_KEY` / `IPROOV_API_SECRET` /
//! `IPROOV_SERVICE_LOCATION`); absent → the feature is disabled and NFC-PID capture fails closed.
//! Secrets are never hard-coded. The wire contract follows the iProov REST API v2 (`/api/v2/claim/…`);
//! the exact field set should be confirmed against the SP account, so the request builders and the
//! response parsers are split out as pure functions and unit-tested.
//!
//! Staged like [`crate::svipe`]: the async wrappers are wired by the capture-session backend; until
//! then the module carries `#[allow(dead_code)]` on its declaration in `main.rs`.

use serde::Deserialize;
use serde_json::{Value, json};

/// GPA assurance level (vs. the weaker `liveness`).
pub const ASSURANCE_GENUINE_PRESENCE: &str = "genuine_presence";
/// Client identifier sent to iProov for this integration.
pub const CLIENT_ID: &str = "eudi-wallet-pid-capture";

/// Trusted iProov Service Provider configuration, loaded from the environment.
#[derive(Clone)]
pub struct IProovConfig {
    api_key: String,
    secret: String,
    /// Regional host, e.g. `eu.rp.secure.iproov.me`.
    service_location: String,
}

impl IProovConfig {
    /// Load from the environment. Returns `None` if any field is unset/empty — the caller then
    /// disables the iProov-gated flow (fail-closed), never a partial configuration.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var("IPROOV_API_KEY")
            .ok()
            .filter(|v| !v.is_empty())?;
        let secret = std::env::var("IPROOV_API_SECRET")
            .ok()
            .filter(|v| !v.is_empty())?;
        let service_location = std::env::var("IPROOV_SERVICE_LOCATION")
            .ok()
            .filter(|v| !v.is_empty())?;
        Some(Self {
            api_key,
            secret,
            service_location,
        })
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            api_key: "test-api-key".into(),
            secret: "test-secret".into(),
            service_location: "eu.rp.secure.iproov.me".into(),
        }
    }

    #[must_use]
    pub fn token_endpoint(&self) -> String {
        format!(
            "https://{}/api/v2/claim/verify/token",
            self.service_location
        )
    }

    #[must_use]
    pub fn validate_endpoint(&self) -> String {
        format!(
            "https://{}/api/v2/claim/verify/validate",
            self.service_location
        )
    }

    /// The SDK streaming URL for this SP region (`IProov.launch(streamingURL:)`).
    #[must_use]
    pub fn streaming_url(&self) -> String {
        format!("wss://{}/ws", self.service_location)
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
        "assurance_type": ASSURANCE_GENUINE_PRESENCE,
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
}

/// Reduce a `claim/verify/validate` response to the authoritative liveness verdict. A genuine failed
/// capture is a `200` with `passed:false`; a malformed request is surfaced as an HTTP error by the
/// async wrapper before this is reached.
pub fn parse_validate_response(body: &str) -> Result<bool, String> {
    let parsed: ValidateResponse =
        serde_json::from_str(body).map_err(|e| format!("iproov validate response: {e}"))?;
    Ok(parsed.passed)
}

/// Mint a GPA verify token for a capture session (server-to-server).
#[allow(dead_code)]
pub async fn create_token(
    client: &reqwest::Client,
    cfg: &IProovConfig,
    user_id: &str,
    resource: &str,
) -> Result<String, String> {
    let response = client
        .post(cfg.token_endpoint())
        .json(&token_request_body(cfg, user_id, resource))
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

/// Validate a completed capture → the authoritative `liveness_matched` verdict.
#[allow(dead_code)]
pub async fn validate(
    client: &reqwest::Client,
    cfg: &IProovConfig,
    token: &str,
    user_id: &str,
    client_ip: &str,
) -> Result<bool, String> {
    let response = client
        .post(cfg.validate_endpoint())
        .json(&validate_request_body(cfg, token, user_id, client_ip))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    parse_validate_response(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_and_streaming_url_are_regional() {
        let cfg = IProovConfig::for_test();
        assert_eq!(
            cfg.token_endpoint(),
            "https://eu.rp.secure.iproov.me/api/v2/claim/verify/token"
        );
        assert_eq!(
            cfg.validate_endpoint(),
            "https://eu.rp.secure.iproov.me/api/v2/claim/verify/validate"
        );
        assert_eq!(cfg.streaming_url(), "wss://eu.rp.secure.iproov.me/ws");
    }

    #[test]
    fn token_body_carries_sp_key_and_genuine_presence() {
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
    fn parses_validate_verdict() {
        assert!(parse_validate_response(r#"{"passed":true}"#).unwrap());
        assert!(
            !parse_validate_response(r#"{"passed":false,"failure_reason":"user_timeout"}"#)
                .unwrap()
        );
        // A response without the field is treated as not-passed (fail-closed).
        assert!(!parse_validate_response(r#"{"other":1}"#).unwrap());
        assert!(parse_validate_response("not json").is_err());
    }
}
