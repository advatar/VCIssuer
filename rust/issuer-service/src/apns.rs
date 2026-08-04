//! Apple Push Notification service (APNs) provider — token-based (JWT) auth over HTTP/2.
//!
//! `VCIssuer` notifies the wallet on real events (e.g. a cross-wallet PID capture becoming issued,
//! or a credential offer being ready). The provider token is an ES256 JWT signed with the APNs
//! auth key (a `.p8` P-256 key), and pushes go to `api.push.apple.com` (prod) or
//! `api.sandbox.push.apple.com` (dev) at `/3/device/{token}`.
//!
//! Config (env, all required; absent ⇒ [`ApnsConfig::from_env`] is `None` and pushes are disabled):
//! `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_TOPIC` (the app bundle id), `APNS_KEY_P8_PATH` (path to the
//! `.p8`), `APNS_ENVIRONMENT` (`sandbox` | `production`, default `production`). The key never leaves
//! the process; only the short-lived JWT is sent.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::DecodePrivateKey;
use serde_json::{Value, json};

#[derive(Clone)]
pub struct ApnsConfig {
    team_id: String,
    key_id: String,
    topic: String,
    host: &'static str,
    signing_key: SigningKey,
}

impl ApnsConfig {
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let team_id = crate::env_file::var("APNS_TEAM_ID").filter(|v| !v.is_empty())?;
        let key_id = crate::env_file::var("APNS_KEY_ID").filter(|v| !v.is_empty())?;
        let topic = crate::env_file::var("APNS_TOPIC").filter(|v| !v.is_empty())?;
        let path = crate::env_file::var("APNS_KEY_P8_PATH").filter(|v| !v.is_empty())?;
        let host = match crate::env_file::var("APNS_ENVIRONMENT").as_deref() {
            Some("sandbox" | "development") => "api.sandbox.push.apple.com",
            _ => "api.push.apple.com",
        };
        let pem = std::fs::read_to_string(&path).ok()?;
        let signing_key = SigningKey::from_pkcs8_pem(&pem).ok()?;
        Some(Self {
            team_id,
            key_id,
            topic,
            host,
            signing_key,
        })
    }

    #[cfg(test)]
    fn for_test(signing_key: SigningKey) -> Self {
        Self {
            team_id: "TEAM123456".into(),
            key_id: "KEY1234567".into(),
            topic: "eu.advatar.wallet".into(),
            host: "api.sandbox.push.apple.com",
            signing_key,
        }
    }

    /// Build the ES256 provider JWT (header `{alg:ES256, kid}`, claims `{iss:team, iat}`) with the
    /// raw (r‖s) JWS signature. Regenerated per push; APNs accepts it for up to an hour.
    #[must_use]
    pub fn provider_token(&self, now_unix: u64) -> String {
        let header = json!({ "alg": "ES256", "kid": self.key_id, "typ": "JWT" });
        let claims = json!({ "iss": self.team_id, "iat": now_unix });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header serializes")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize")),
        );
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    /// Send a notification to one device token (server-to-server, HTTP/2).
    pub async fn send(
        &self,
        client: &reqwest::Client,
        device_token: &str,
        payload: &Value,
        now_unix: u64,
    ) -> Result<(), String> {
        let url = format!("https://{}/3/device/{device_token}", self.host);
        let response = client
            .post(url)
            .header(
                "authorization",
                format!("bearer {}", self.provider_token(now_unix)),
            )
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .json(payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(format!("APNs returned {status}: {body}"))
        }
    }
}

/// A simple alert payload (title + body). No credential data — status only.
#[must_use]
pub fn alert_payload(title: &str, body: &str) -> Value {
    json!({ "aps": { "alert": { "title": title, "body": body }, "sound": "default" } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn provider_token_is_a_verifiable_es256_jwt() {
        let sk = SigningKey::from_slice(&[3u8; 32]).expect("key");
        let cfg = ApnsConfig::for_test(sk.clone());
        let token = cfg.provider_token(1_700_000_000);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Header + claims decode with the expected fields.
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY1234567");
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["iat"], 1_700_000_000);

        // The raw (r‖s) signature verifies over "header.claims".
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = Signature::from_slice(&sig_bytes).expect("64-byte sig");
        let vk: VerifyingKey = *sk.verifying_key();
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn alert_payload_has_aps_alert() {
        let p = alert_payload("PID ready", "Your document was issued.");
        assert_eq!(p["aps"]["alert"]["title"], "PID ready");
        assert_eq!(p["aps"]["alert"]["body"], "Your document was issued.");
    }
}
