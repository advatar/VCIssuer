#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod signer;

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::Value as CborValue;
use issuer_core::{
    Authorization, CredentialFormat, CredentialProfile, CredentialProof, DatasetId, Evidence,
    Instant, IssuerRole, KeyThumbprint, NonceId, ProfileId, Request, RequestId, Session, SessionId,
    SubjectEvidence, SubjectId, TokenBinding, WalletEvidence, authorize_sign,
};
use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Mutex;
use tracing::info;
use url::Url;
use uuid::Uuid;

#[cfg(target_os = "macos")]
use signer::KeychainSigner;

const PID_SD_JWT: &str = "eu.europa.ec.eudi.pid_vc_sd_jwt.de";
const PID_MDOC: &str = "eu.europa.ec.eudi.pid_mso_mdoc.de";
const EAA_MDOC: &str = "org.iso.18013.5.1.mDL.de";
const QEAA_SD_JWT: &str = "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt:de";

#[derive(Clone)]
struct AppState {
    issuer: Url,
    inner: Arc<Mutex<VolatileState>>,
    #[cfg(target_os = "macos")]
    metadata_signer: Arc<KeychainSigner>,
    #[cfg(target_os = "macos")]
    credential_signers: Arc<HashMap<&'static str, KeychainSigner>>,
}

#[derive(Default)]
struct VolatileState {
    pushed: HashMap<String, PushedAuthorization>,
    codes: HashMap<String, AuthorizationCode>,
    tokens: HashMap<String, AccessToken>,
    nonces: HashMap<String, bool>,
    dpop_jtis: HashSet<String>,
}

#[derive(Clone)]
struct PushedAuthorization {
    client_id: String,
    redirect_uri: Url,
    scope: String,
    state: Option<String>,
    code_challenge: String,
}

struct AuthorizationCode {
    client_id: String,
    redirect_uri: Url,
    scope: String,
    code_challenge: String,
    consumed: bool,
}

struct AccessToken {
    scope: String,
    dpop_jkt: String,
}

#[derive(Deserialize)]
struct ParRequest {
    client_id: String,
    redirect_uri: Url,
    response_type: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Serialize)]
struct ParResponse {
    request_uri: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct AuthorizationRequest {
    client_id: String,
    request_uri: String,
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: Url,
    client_id: String,
    code_verifier: String,
}

#[derive(Deserialize)]
struct CredentialRequest {
    credential_configuration_id: String,
    proof: CredentialProofObject,
}

#[derive(Deserialize)]
struct CredentialProofObject {
    proof_type: String,
    jwt: String,
}

#[derive(Deserialize)]
struct DpopHeader {
    alg: String,
    typ: String,
    jwk: EcJwk,
}

#[derive(Deserialize)]
struct EcJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: u64,
    jti: String,
}

#[derive(Deserialize)]
struct CredentialProofClaims {
    aud: String,
    iat: u64,
    nonce: String,
}

struct VerifiedCredentialProof {
    holder_jkt: String,
    holder_jwk: Value,
    nonce: String,
}

#[derive(Debug, Serialize)]
struct OAuthError {
    error: &'static str,
    error_description: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let issuer = std::env::var("ISSUER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let issuer = Url::parse(&issuer).expect("ISSUER_URL must be an absolute URL");
    let address: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .expect("LISTEN_ADDR must be a socket address");

    #[cfg(target_os = "macos")]
    let credential_signers = [PID_SD_JWT, PID_MDOC, EAA_MDOC, QEAA_SD_JWT]
        .into_iter()
        .map(|profile| {
            let label = format!("dev.advatar.vcissuer.{}", key_label(profile));
            KeychainSigner::find_or_create(&label).map_or_else(
                |error| panic!("credential signing key {label} is unavailable: {error}"),
                |signer| (profile, signer),
            )
        })
        .collect();

    let app = app(AppState {
        issuer,
        inner: Arc::new(Mutex::new(VolatileState::default())),
        #[cfg(target_os = "macos")]
        metadata_signer: Arc::new(
            KeychainSigner::find_or_create("dev.advatar.vcissuer.metadata")
                .expect("metadata signing key must be available in macOS Keychain"),
        ),
        #[cfg(target_os = "macos")]
        credential_signers: Arc::new(credential_signers),
    });
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("listen address must be available");
    info!(%address, "German EUDI development issuer listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("HTTP server failed");
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_metadata),
        )
        .route("/jwks.json", get(jwks))
        .route("/par", post(par))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/nonce", post(nonce))
        .route("/credential", post(credential))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "mode": "development"}))
}

async fn issuer_metadata(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<OAuthError>)> {
    let mut metadata = issuer_metadata_value(&state);
    #[cfg(target_os = "macos")]
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "system clock is before the Unix epoch",
                )
            })?
            .as_secs();
        let mut claims = metadata.clone();
        let object = claims
            .as_object_mut()
            .expect("issuer metadata is always an object");
        object.insert("iss".into(), json!(state.issuer.as_str()));
        object.insert("sub".into(), json!(state.issuer.as_str()));
        object.insert("iat".into(), json!(now));
        let protected = json!({
            "alg": "ES256",
            "typ": "openidvci-issuer-metadata+jwt",
            "kid": state.metadata_signer.kid()
        });
        let protected = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&protected).expect("protected header is serializable"));
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).expect("metadata claims are serializable"));
        let signing_input = format!("{protected}.{payload}");
        let signature = state
            .metadata_signer
            .sign_es256(signing_input.as_bytes())
            .map_err(|error| {
                tracing::error!(%error, "metadata signing failed");
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "signed metadata is unavailable",
                )
            })?;
        metadata
            .as_object_mut()
            .expect("issuer metadata is always an object")
            .insert(
                "signed_metadata".into(),
                json!(format!(
                    "{signing_input}.{}",
                    URL_SAFE_NO_PAD.encode(signature)
                )),
            );
    }
    Ok(Json(metadata))
}

fn issuer_metadata_value(state: &AppState) -> Value {
    let issuer = state.issuer.as_str().trim_end_matches('/');
    json!({
        "credential_issuer": issuer,
        "authorization_servers": [issuer],
        "credential_endpoint": format!("{issuer}/credential"),
        "nonce_endpoint": format!("{issuer}/nonce"),
        "batch_credential_issuance": {"batch_size": 1},
        "credential_configurations_supported": {
            PID_SD_JWT: sd_jwt_profile(PID_SD_JWT, "eu.europa.ec.eudi.pid.1", "German PID (SD-JWT VC)"),
            PID_MDOC: mdoc_profile(PID_MDOC, "eu.europa.ec.eudi.pid.1", "German PID (mdoc)"),
            EAA_MDOC: mdoc_profile(EAA_MDOC, "org.iso.18013.5.1.mDL", "German driving licence EAA (mdoc)"),
            QEAA_SD_JWT: sd_jwt_profile(QEAA_SD_JWT, "urn:eu.europa.ec.eudi:learning:credential:1", "German learning QEAA (SD-JWT VC)")
        }
    })
}

fn sd_jwt_profile(configuration_id: &str, vct: &str, name: &str) -> Value {
    json!({
        "format": "dc+sd-jwt",
        "scope": configuration_id,
        "vct": vct,
        "cryptographic_binding_methods_supported": ["jwk"],
        "credential_signing_alg_values_supported": ["ES256"],
        "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
        "display": [{"name": name, "locale": "de-DE"}]
    })
}

fn mdoc_profile(configuration_id: &str, doc_type: &str, name: &str) -> Value {
    json!({
        "format": "mso_mdoc",
        "scope": configuration_id,
        "doctype": doc_type,
        "cryptographic_binding_methods_supported": ["cose_key"],
        "credential_signing_alg_values_supported": ["ES256"],
        "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
        "display": [{"name": name, "locale": "de-DE"}]
    })
}

async fn oauth_metadata(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.issuer.as_str().trim_end_matches('/');
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"]
    }))
}

#[cfg(target_os = "macos")]
async fn jwks(State(state): State<AppState>) -> Json<Value> {
    let mut keys = vec![state.metadata_signer.public_jwk()];
    keys.extend(
        state
            .credential_signers
            .values()
            .map(KeychainSigner::public_jwk),
    );
    Json(json!({"keys": keys}))
}

#[cfg(not(target_os = "macos"))]
async fn jwks() -> Json<Value> {
    Json(json!({"keys": []}))
}

async fn par(
    State(state): State<AppState>,
    Form(request): Form<ParRequest>,
) -> Result<Json<ParResponse>, (StatusCode, Json<OAuthError>)> {
    if request.response_type != "code" || request.code_challenge_method != "S256" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "response_type=code and PKCE S256 are required",
        ));
    }
    if !valid_scope(&request.scope) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope contains an unsupported credential",
        ));
    }
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::new_v4());
    state.inner.lock().await.pushed.insert(
        request_uri.clone(),
        PushedAuthorization {
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            scope: request.scope,
            state: request.state,
            code_challenge: request.code_challenge,
        },
    );
    Ok(Json(ParResponse {
        request_uri,
        expires_in: 60,
    }))
}

async fn authorize(
    State(state): State<AppState>,
    Query(request): Query<AuthorizationRequest>,
) -> Result<Redirect, (StatusCode, Json<OAuthError>)> {
    let pushed = state
        .inner
        .lock()
        .await
        .pushed
        .remove(&request.request_uri)
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_uri",
                "unknown or consumed request_uri",
            )
        })?;
    if pushed.client_id != request.client_id {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id does not match PAR",
        ));
    }
    let code = random_token();
    state.inner.lock().await.codes.insert(
        code.clone(),
        AuthorizationCode {
            client_id: pushed.client_id,
            redirect_uri: pushed.redirect_uri.clone(),
            scope: pushed.scope,
            code_challenge: pushed.code_challenge,
            consumed: false,
        },
    );
    let mut redirect = pushed.redirect_uri;
    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(value) = pushed.state {
        redirect.query_pairs_mut().append_pair("state", &value);
    }
    Ok(Redirect::to(redirect.as_str()))
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<Json<Value>, (StatusCode, Json<OAuthError>)> {
    if request.grant_type != "authorization_code" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only authorization_code is enabled",
        ));
    }
    let dpop = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "DPoP proof is required",
            )
        })?;
    let token_endpoint = state
        .issuer
        .join("token")
        .expect("static endpoint must be a valid URL");
    let verified_dpop = verify_dpop(dpop, "POST", &token_endpoint)?;
    let mut inner = state.inner.lock().await;
    if !inner.dpop_jtis.insert(verified_dpop.jti) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP jti has already been used",
        ));
    }
    let code = inner.codes.get_mut(&request.code).ok_or_else(|| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "unknown authorization code",
        )
    })?;
    if code.consumed
        || code.client_id != request.client_id
        || code.redirect_uri != request.redirect_uri
        || !pkce_matches(&request.code_verifier, &code.code_challenge)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code binding failed",
        ));
    }
    code.consumed = true;
    let scope = code.scope.clone();
    let access_token = random_token();
    inner.tokens.insert(
        access_token.clone(),
        AccessToken {
            scope: scope.clone(),
            dpop_jkt: verified_dpop.jkt,
        },
    );
    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "DPoP",
        "expires_in": 300,
        "scope": scope
    })))
}

async fn nonce(State(state): State<AppState>) -> Json<Value> {
    let nonce = random_token();
    state.inner.lock().await.nonces.insert(nonce.clone(), false);
    Json(json!({"c_nonce": nonce, "c_nonce_expires_in": 300}))
}

#[allow(clippy::too_many_lines)]
async fn credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CredentialRequest>,
) -> Result<Json<Value>, (StatusCode, Json<OAuthError>)> {
    let token = bearer(&headers)?;
    let dpop = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "DPoP proof is required",
            )
        })?;
    let credential_endpoint = state
        .issuer
        .join("credential")
        .expect("static endpoint must be a valid URL");
    let verified_dpop = verify_dpop(dpop, "POST", &credential_endpoint)?;
    let mut inner = state.inner.lock().await;
    if !inner.dpop_jtis.insert(verified_dpop.jti) {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_dpop_proof",
            "DPoP jti has already been used",
        ));
    }
    let access = inner.tokens.get(token).ok_or_else(|| {
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "access token is unknown",
        )
    })?;
    if access
        .dpop_jkt
        .as_bytes()
        .ct_eq(verified_dpop.jkt.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "DPoP key binding mismatch",
        ));
    }
    if !access
        .scope
        .split_ascii_whitespace()
        .any(|s| s == request.credential_configuration_id)
    {
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "credential_request_denied",
            "credential is outside the authorized scope",
        ));
    }
    if request.proof.proof_type != "jwt" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "a JWT credential proof is required",
        ));
    }
    let verified_proof = verify_credential_proof(&request.proof.jwt, &state.issuer)?;
    if access
        .dpop_jkt
        .as_bytes()
        .ct_eq(verified_proof.holder_jkt.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "development profile requires the credential proof and DPoP key to match",
        ));
    }
    let nonce_used = inner.nonces.get_mut(&verified_proof.nonce).ok_or_else(|| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof nonce is unknown",
        )
    })?;
    if *nonce_used {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof nonce has already been used",
        ));
    }
    let now = unix_time()?;
    authorize_kernel(
        &request.credential_configuration_id,
        &verified_proof.holder_jkt,
        &verified_proof.nonce,
        now,
    )?;
    *nonce_used = true;
    drop(inner);

    match request.credential_configuration_id.as_str() {
        PID_SD_JWT | QEAA_SD_JWT => {
            #[cfg(target_os = "macos")]
            {
                let signer = state
                    .credential_signers
                    .get(request.credential_configuration_id.as_str())
                    .expect("closed profile has a signer");
                let credential = issue_sd_jwt(
                    signer,
                    &state.issuer,
                    &request.credential_configuration_id,
                    &verified_proof.holder_jwk,
                    now,
                )?;
                Ok(Json(json!({"credentials": [{"credential": credential}]})))
            }
            #[cfg(not(target_os = "macos"))]
            Err(oauth_error(
                StatusCode::NOT_IMPLEMENTED,
                "credential_request_denied",
                "this development build requires macOS Keychain",
            ))
        }
        PID_MDOC | EAA_MDOC => {
            #[cfg(target_os = "macos")]
            {
                let signer = state
                    .credential_signers
                    .get(request.credential_configuration_id.as_str())
                    .expect("closed profile has a signer");
                let credential = issue_mdoc(
                    signer,
                    &request.credential_configuration_id,
                    &verified_proof.holder_jwk,
                    now,
                )?;
                Ok(Json(json!({"credentials": [{"credential": credential}]})))
            }
            #[cfg(not(target_os = "macos"))]
            Err(oauth_error(
                StatusCode::NOT_IMPLEMENTED,
                "credential_request_denied",
                "this development build requires macOS Keychain",
            ))
        }
        _ => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unknown_credential_configuration",
            "credential configuration is unknown",
        )),
    }
}

fn valid_scope(scope: &str) -> bool {
    let allowed = [PID_SD_JWT, PID_MDOC, EAA_MDOC, QEAA_SD_JWT];
    let mut count = 0;
    for item in scope.split_ascii_whitespace() {
        count += 1;
        if !allowed.contains(&item) {
            return false;
        }
    }
    count > 0
}

fn key_label(profile: &str) -> &'static str {
    match profile {
        PID_SD_JWT => "pid-sd-jwt",
        PID_MDOC => "pid-mdoc",
        EAA_MDOC => "eaa-mdoc",
        QEAA_SD_JWT => "qeaa-sd-jwt",
        _ => unreachable!("only closed profile identifiers are used"),
    }
}

fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let calculated = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    calculated
        .as_bytes()
        .ct_eq(challenge.as_bytes())
        .unwrap_u8()
        == 1
}

fn random_token() -> String {
    let mut value = [0_u8; 32];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn bearer(headers: &HeaderMap) -> Result<&str, (StatusCode, Json<OAuthError>)> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("DPoP "))
        .ok_or_else(|| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "DPoP access token is required",
            )
        })
}

struct VerifiedDpop {
    jkt: String,
    jti: String,
}

#[allow(clippy::too_many_lines)]
fn verify_credential_proof(
    proof: &str,
    issuer: &Url,
) -> Result<VerifiedCredentialProof, (StatusCode, Json<OAuthError>)> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof must be a three-part compact JWS",
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof header is malformed",
        )
    })?;
    let header: DpopHeader = serde_json::from_slice(&header_bytes).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof header is not valid JSON",
        )
    })?;
    if header.alg != "ES256" || header.typ != "openid4vci-proof+jwt" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof must use typ=openid4vci-proof+jwt and alg=ES256",
        ));
    }
    let (verifying_key, jkt, jwk) = verifying_key_and_jwk(&header.jwk, "invalid_proof")?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof signature is malformed",
        )
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof signature must be ES256",
        )
    })?;
    verifying_key
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "credential proof signature verification failed",
            )
        })?;
    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof claims are malformed",
        )
    })?;
    let claims: CredentialProofClaims = serde_json::from_slice(&claims_bytes).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof claims are not valid JSON",
        )
    })?;
    if claims.aud.trim_end_matches('/') != issuer.as_str().trim_end_matches('/') {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof audience does not match the issuer",
        ));
    }
    let now = unix_time()?;
    if claims.iat > now.saturating_add(5) || now.saturating_sub(claims.iat) > 300 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof iat is outside the accepted freshness window",
        ));
    }
    if claims.nonce.is_empty() || claims.nonce.len() > 256 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof nonce is missing or too long",
        ));
    }
    Ok(VerifiedCredentialProof {
        holder_jkt: jkt,
        holder_jwk: jwk,
        nonce: claims.nonce,
    })
}

fn verifying_key_and_jwk(
    jwk: &EcJwk,
    error_code: &'static str,
) -> Result<(VerifyingKey, String, Value), (StatusCode, Json<OAuthError>)> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            error_code,
            "JWK must be an EC P-256 public key",
        ));
    }
    let x = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|_| oauth_error(StatusCode::BAD_REQUEST, error_code, "JWK x is malformed"))?;
    let y = URL_SAFE_NO_PAD
        .decode(&jwk.y)
        .map_err(|_| oauth_error(StatusCode::BAD_REQUEST, error_code, "JWK y is malformed"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            error_code,
            "P-256 coordinates must be 32 octets",
        ));
    }
    let point =
        EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
    let key = VerifyingKey::from_encoded_point(&point).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            error_code,
            "JWK is not a valid P-256 point",
        )
    })?;
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.x, jwk.y
    );
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    Ok((
        key,
        jkt,
        json!({"kty":"EC", "crv":"P-256", "x":jwk.x, "y":jwk.y}),
    ))
}

fn unix_time() -> Result<u64, (StatusCode, Json<OAuthError>)> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "system clock is before the Unix epoch",
            )
        })
}

#[allow(clippy::too_many_lines)]
fn authorize_kernel(
    profile_name: &str,
    holder_jkt: &str,
    nonce: &str,
    now: u64,
) -> Result<(), (StatusCode, Json<OAuthError>)> {
    let role = match profile_name {
        PID_SD_JWT | PID_MDOC => IssuerRole::Pid,
        QEAA_SD_JWT => IssuerRole::Qeaa,
        EAA_MDOC => IssuerRole::NonQualifiedEaa,
        _ => {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "unknown_credential_configuration",
                "credential configuration is unknown",
            ));
        }
    };
    let format = match profile_name {
        PID_SD_JWT | QEAA_SD_JWT => CredentialFormat::SdJwtVc,
        PID_MDOC | EAA_MDOC => CredentialFormat::Mdoc,
        _ => unreachable!("profile was checked above"),
    };
    let profile_id = ProfileId(hash_u128(profile_name));
    let holder_key = KeyThumbprint(hash_u128(holder_jkt));
    let nonce_id = NonceId(hash_u128(nonce));
    let subject = SubjectId(1);
    let dataset = DatasetId(hash_u128(profile_name));
    let evidence = Evidence {
        valid_from: Instant(now.saturating_sub(1)),
        valid_until: Instant(now.saturating_add(300)),
        fresh_until: Instant(now.saturating_add(60)),
        accepted: true,
    };
    let profile = CredentialProfile {
        id: profile_id,
        role,
        format,
        enabled: true,
        device_binding_required: true,
    };
    let proof = CredentialProof {
        evidence,
        nonce: nonce_id,
        holder_key,
        possession_valid: true,
    };
    let request = Request {
        id: RequestId(hash_u128(&random_token())),
        profile: profile_id,
        subject,
        dataset,
        dpop_key: holder_key,
        proof,
        expiry: Instant(now.saturating_add(3600)),
    };
    let session = Session {
        id: SessionId(hash_u128(&random_token())),
        profile,
        authorization: Authorization {
            evidence,
            profile: profile_id,
            subject,
            dataset,
        },
        token: TokenBinding {
            evidence,
            dpop_key: holder_key,
        },
        wallet: WalletEvidence {
            wia: evidence,
            ka: Some(evidence),
            wallet_not_revoked: true,
            holder_key_approved: true,
        },
        subject: SubjectEvidence {
            evidence,
            subject,
            loa_high: true,
            entitled: true,
            claims_current: true,
            dataset,
        },
        expected_nonce: nonce_id,
        nonce_unused: true,
        issuer_entitled: true,
        status_reserved: true,
        already_issued: false,
        wia_ka_maintenance_end: Instant(now.saturating_add(86_400)),
    };
    authorize_sign(session, request, Instant(now)).map_err(|_| {
        oauth_error(
            StatusCode::FORBIDDEN,
            "credential_request_denied",
            "verified issuer kernel denied the signing command",
        )
    })?;
    Ok(())
}

fn hash_u128(value: &str) -> u128 {
    let digest = Sha256::digest(value.as_bytes());
    u128::from_be_bytes(digest[..16].try_into().expect("slice length is fixed"))
}

#[cfg(target_os = "macos")]
fn issue_sd_jwt(
    signer: &KeychainSigner,
    issuer: &Url,
    profile: &str,
    holder_jwk: &Value,
    now: u64,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let (vct, claims) = match profile {
        PID_SD_JWT => (
            "eu.europa.ec.eudi.pid.1",
            vec![
                ("family_name", json!("Mustermann")),
                ("given_name", json!("Erika")),
                ("birthdate", json!("1990-01-01")),
                ("age_over_18", json!(true)),
                ("issuing_country", json!("DE")),
            ],
        ),
        QEAA_SD_JWT => (
            "urn:eu.europa.ec.eudi:learning:credential:1",
            vec![
                ("credential_name", json!("Hochschulabschluss")),
                ("awarding_body", json!("German Development University")),
                ("qualification", json!("Master of Science")),
                ("issuing_country", json!("DE")),
            ],
        ),
        _ => unreachable!("only SD-JWT profiles call this encoder"),
    };
    let mut disclosures = Vec::new();
    let mut digests = Vec::new();
    for (name, value) in claims {
        let disclosure = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!([random_token(), name, value]))
                .expect("disclosure is serializable"),
        );
        digests.push(URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes())));
        disclosures.push(disclosure);
    }
    let payload = json!({
        "iss": issuer.as_str().trim_end_matches('/'),
        "iat": now,
        "nbf": now,
        "exp": now.saturating_add(3600),
        "vct": vct,
        "cnf": {"jwk": holder_jwk},
        "_sd_alg": "sha-256",
        "_sd": digests
    });
    let header = json!({"alg":"ES256", "typ":"dc+sd-jwt", "kid":signer.kid()});
    let protected =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header is serializable"));
    let payload =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload is serializable"));
    let input = format!("{protected}.{payload}");
    let signature = signer.sign_es256(input.as_bytes()).map_err(|error| {
        tracing::error!(%error, "credential signing failed");
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "credential signing is unavailable",
        )
    })?;
    Ok(format!(
        "{input}.{}~{}~",
        URL_SAFE_NO_PAD.encode(signature),
        disclosures.join("~")
    ))
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_lines)]
fn issue_mdoc(
    signer: &KeychainSigner,
    profile: &str,
    holder_jwk: &Value,
    now: u64,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let (doc_type, namespace, claims): (&str, &str, Vec<(&str, CborValue)>) = match profile {
        PID_MDOC => (
            "eu.europa.ec.eudi.pid.1",
            "eu.europa.ec.eudi.pid.1",
            vec![
                ("family_name", CborValue::Text("Mustermann".into())),
                ("given_name", CborValue::Text("Erika".into())),
                ("birth_date", CborValue::Text("1990-01-01".into())),
                ("age_over_18", CborValue::Bool(true)),
                ("issuing_country", CborValue::Text("DE".into())),
            ],
        ),
        EAA_MDOC => (
            "org.iso.18013.5.1.mDL",
            "org.iso.18013.5.1",
            vec![
                ("family_name", CborValue::Text("Mustermann".into())),
                ("given_name", CborValue::Text("Erika".into())),
                ("birth_date", CborValue::Text("1990-01-01".into())),
                ("issuing_country", CborValue::Text("DE".into())),
                ("document_number", CborValue::Text("DEV-MDL-0001".into())),
            ],
        ),
        _ => unreachable!("only mdoc profiles call this encoder"),
    };

    let mut issuer_items = Vec::new();
    let mut digest_entries = Vec::new();
    for (digest_id, (element_identifier, element_value)) in claims.into_iter().enumerate() {
        let item = CborValue::Map(vec![
            (
                CborValue::Text("digestID".into()),
                cbor_uint(digest_id as u64),
            ),
            (
                CborValue::Text("random".into()),
                CborValue::Bytes(random_bytes(32)),
            ),
            (
                CborValue::Text("elementIdentifier".into()),
                CborValue::Text(element_identifier.into()),
            ),
            (CborValue::Text("elementValue".into()), element_value),
        ]);
        let item_bytes = cbor_encode(&item)?;
        let tagged_item = CborValue::Tag(24, Box::new(CborValue::Bytes(item_bytes)));
        let tagged_bytes = cbor_encode(&tagged_item)?;
        digest_entries.push((
            cbor_uint(digest_id as u64),
            CborValue::Bytes(Sha256::digest(&tagged_bytes).to_vec()),
        ));
        issuer_items.push(tagged_item);
    }

    let holder_x = decode_jwk_coordinate(holder_jwk, "x")?;
    let holder_y = decode_jwk_coordinate(holder_jwk, "y")?;
    let device_key = CborValue::Map(vec![
        (cbor_int(1), cbor_int(2)),
        (cbor_int(-1), cbor_int(1)),
        (cbor_int(-2), CborValue::Bytes(holder_x)),
        (cbor_int(-3), CborValue::Bytes(holder_y)),
    ]);
    let signed_at = rfc3339(now)?;
    let valid_until = rfc3339(now.saturating_add(3600))?;
    let mso = CborValue::Map(vec![
        (
            CborValue::Text("version".into()),
            CborValue::Text("1.0".into()),
        ),
        (
            CborValue::Text("digestAlgorithm".into()),
            CborValue::Text("SHA-256".into()),
        ),
        (
            CborValue::Text("valueDigests".into()),
            CborValue::Map(vec![(
                CborValue::Text(namespace.into()),
                CborValue::Map(digest_entries),
            )]),
        ),
        (
            CborValue::Text("deviceKeyInfo".into()),
            CborValue::Map(vec![(CborValue::Text("deviceKey".into()), device_key)]),
        ),
        (
            CborValue::Text("docType".into()),
            CborValue::Text(doc_type.into()),
        ),
        (
            CborValue::Text("validityInfo".into()),
            CborValue::Map(vec![
                (CborValue::Text("signed".into()), cbor_datetime(&signed_at)),
                (
                    CborValue::Text("validFrom".into()),
                    cbor_datetime(&signed_at),
                ),
                (
                    CborValue::Text("validUntil".into()),
                    cbor_datetime(&valid_until),
                ),
            ]),
        ),
    ]);
    let mso_payload = cbor_encode(&CborValue::Tag(
        24,
        Box::new(CborValue::Bytes(cbor_encode(&mso)?)),
    ))?;
    let protected = cbor_encode(&CborValue::Map(vec![
        (cbor_int(1), cbor_int(-7)),
        (
            cbor_int(4),
            CborValue::Bytes(signer.kid().as_bytes().to_vec()),
        ),
    ]))?;
    let sig_structure = CborValue::Array(vec![
        CborValue::Text("Signature1".into()),
        CborValue::Bytes(protected.clone()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(mso_payload.clone()),
    ]);
    let signature = signer
        .sign_es256(&cbor_encode(&sig_structure)?)
        .map_err(|error| {
            tracing::error!(%error, "mdoc signing failed");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "mdoc signing is unavailable",
            )
        })?;
    let certificate_label = format!("dev.advatar.vcissuer.{}", key_label(profile));
    let certificate =
        KeychainSigner::development_certificate_der(&certificate_label).map_err(|error| {
            tracing::error!(%error, "mdoc development certificate generation failed");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "mdoc issuer certificate is unavailable",
            )
        })?;
    let issuer_auth = CborValue::Tag(
        18,
        Box::new(CborValue::Array(vec![
            CborValue::Bytes(protected),
            CborValue::Map(vec![(
                cbor_int(33),
                CborValue::Array(vec![CborValue::Bytes(certificate)]),
            )]),
            CborValue::Bytes(mso_payload),
            CborValue::Bytes(signature.to_vec()),
        ])),
    );
    let issuer_signed = CborValue::Map(vec![
        (
            CborValue::Text("nameSpaces".into()),
            CborValue::Map(vec![(
                CborValue::Text(namespace.into()),
                CborValue::Array(issuer_items),
            )]),
        ),
        (CborValue::Text("issuerAuth".into()), issuer_auth),
    ]);
    Ok(URL_SAFE_NO_PAD.encode(cbor_encode(&issuer_signed)?))
}

fn cbor_encode(value: &CborValue) -> Result<Vec<u8>, (StatusCode, Json<OAuthError>)> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded).map_err(|error| {
        tracing::error!(%error, "CBOR encoding failed");
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "credential CBOR encoding failed",
        )
    })?;
    Ok(encoded)
}

fn cbor_int(value: i64) -> CborValue {
    CborValue::Integer(value.into())
}

fn cbor_uint(value: u64) -> CborValue {
    CborValue::Integer(value.into())
}

fn cbor_datetime(value: &str) -> CborValue {
    CborValue::Tag(0, Box::new(CborValue::Text(value.into())))
}

fn random_bytes(length: usize) -> Vec<u8> {
    let mut value = vec![0_u8; length];
    rand::rng().fill_bytes(&mut value);
    value
}

fn decode_jwk_coordinate(
    jwk: &Value,
    name: &str,
) -> Result<Vec<u8>, (StatusCode, Json<OAuthError>)> {
    let encoded = jwk.get(name).and_then(Value::as_str).ok_or_else(|| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "holder JWK coordinate is missing",
        )
    })?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "holder JWK coordinate is malformed",
        )
    })?;
    if decoded.len() != 32 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "holder P-256 coordinate must be 32 octets",
        ));
    }
    Ok(decoded)
}

fn rfc3339(timestamp: u64) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let timestamp = i64::try_from(timestamp).map_err(|_| {
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "credential timestamp is out of range",
        )
    })?;
    let value = OffsetDateTime::from_unix_timestamp(timestamp).map_err(|error| {
        tracing::error!(%error, "credential timestamp conversion failed");
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "credential timestamp conversion failed",
        )
    })?;
    value.format(&Rfc3339).map_err(|error| {
        tracing::error!(%error, "credential timestamp formatting failed");
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "credential timestamp formatting failed",
        )
    })
}

#[allow(clippy::too_many_lines)]
fn verify_dpop(
    proof: &str,
    expected_method: &str,
    expected_uri: &Url,
) -> Result<VerifiedDpop, (StatusCode, Json<OAuthError>)> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP proof must be a three-part compact JWS",
        ));
    }
    let encoded = parts.first().copied().ok_or_else(|| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "malformed compact JWS",
        )
    })?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "malformed protected header",
        )
    })?;
    let header: DpopHeader = serde_json::from_slice(&decoded).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "protected header is not JSON",
        )
    })?;
    if header.alg != "ES256" || header.typ != "dpop+jwt" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP protected header must use typ=dpop+jwt and alg=ES256",
        ));
    }
    if header.jwk.kty != "EC" || header.jwk.crv != "P-256" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP jwk must be an EC P-256 public key",
        ));
    }
    let x = URL_SAFE_NO_PAD.decode(&header.jwk.x).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP jwk x coordinate is malformed",
        )
    })?;
    let y = URL_SAFE_NO_PAD.decode(&header.jwk.y).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP jwk y coordinate is malformed",
        )
    })?;
    if x.len() != 32 || y.len() != 32 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP P-256 coordinates must be 32 octets",
        ));
    }
    let point =
        EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
    let verifying_key = VerifyingKey::from_encoded_point(&point).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP jwk is not a valid P-256 point",
        )
    })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP signature is malformed",
        )
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP signature must be an ES256 signature",
        )
    })?;
    verifying_key
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "DPoP signature verification failed",
            )
        })?;

    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP claims are malformed",
        )
    })?;
    let claims: DpopClaims = serde_json::from_slice(&claims_bytes).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP claims are not valid JSON",
        )
    })?;
    let expected_htu = expected_uri.as_str().trim_end_matches('/');
    if claims.htm != expected_method || claims.htu.trim_end_matches('/') != expected_htu {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP htm or htu does not match this request",
        ));
    }
    if claims.jti.is_empty() || claims.jti.len() > 256 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP jti is missing or too long",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "system clock is before the Unix epoch",
            )
        })?
        .as_secs();
    if claims.iat > now.saturating_add(5) || now.saturating_sub(claims.iat) > 60 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP iat is outside the accepted freshness window",
        ));
    }

    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        header.jwk.x, header.jwk.y
    );
    Ok(VerifiedDpop {
        jkt: URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())),
        jti: claims.jti,
    })
}

fn oauth_error(
    status: StatusCode,
    error: &'static str,
    description: &str,
) -> (StatusCode, Json<OAuthError>) {
    (
        status,
        Json(OAuthError {
            error,
            error_description: description.into(),
        }),
    )
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    #[test]
    fn pkce_s256_matches() {
        assert!(pkce_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn scope_is_closed() {
        assert!(valid_scope(PID_SD_JWT));
        assert!(!valid_scope("openid unknown"));
        assert!(!valid_scope(""));
    }

    #[test]
    fn credential_proof_signature_and_claims_are_verified() {
        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let point = key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate"));
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg":"ES256",
                "typ":"openid4vci-proof+jwt",
                "jwk":{"kty":"EC", "crv":"P-256", "x":x, "y":y}
            }))
            .expect("header"),
        );
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "aud":"http://127.0.0.1:18080",
                "iat":unix_time().expect("clock"),
                "nonce":"test-nonce"
            }))
            .expect("claims"),
        );
        let input = format!("{header}.{payload}");
        let signature: Signature = key.sign(input.as_bytes());
        let proof = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        let verified = verify_credential_proof(
            &proof,
            &Url::parse("http://127.0.0.1:18080").expect("issuer URL"),
        )
        .expect("valid proof");
        assert_eq!(verified.nonce, "test-nonce");
        assert!(!verified.holder_jkt.is_empty());

        let tampered_payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "aud":"http://127.0.0.1:18080",
                "iat":unix_time().expect("clock"),
                "nonce":"other-nonce"
            }))
            .expect("claims"),
        );
        let tampered = format!(
            "{header}.{tampered_payload}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        assert!(
            verify_credential_proof(
                &tampered,
                &Url::parse("http://127.0.0.1:18080").expect("issuer URL")
            )
            .is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "creates and accesses a persistent macOS Keychain key"]
    fn mdoc_encoder_produces_tagged_issuer_signed_cbor() {
        let signer =
            KeychainSigner::find_or_create("dev.advatar.vcissuer.test-mdoc").expect("test signer");
        KeychainSigner::development_certificate_der("dev.advatar.vcissuer.pid-mdoc")
            .expect("development certificate");
        let holder = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let point = holder.verifying_key().to_encoded_point(false);
        let holder_jwk = json!({
            "kty":"EC",
            "crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate")),
            "y":URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate"))
        });
        let credential = issue_mdoc(&signer, PID_MDOC, &holder_jwk, unix_time().expect("clock"))
            .expect("mdoc issuance");
        let bytes = URL_SAFE_NO_PAD.decode(credential).expect("base64url mdoc");
        let decoded: CborValue = ciborium::de::from_reader(bytes.as_slice()).expect("CBOR mdoc");
        let CborValue::Map(entries) = decoded else {
            panic!("IssuerSigned must be a CBOR map");
        };
        assert!(
            entries
                .iter()
                .any(|(key, _)| key.as_text() == Some("nameSpaces"))
        );
        assert!(entries.iter().any(|(key, value)| {
            key.as_text() == Some("issuerAuth") && matches!(value, CborValue::Tag(18, _))
        }));

        let issuer_auth = entries
            .iter()
            .find_map(|(key, value)| (key.as_text() == Some("issuerAuth")).then_some(value))
            .expect("issuerAuth");
        let CborValue::Tag(18, cose) = issuer_auth else {
            panic!("issuerAuth must be tagged COSE_Sign1");
        };
        let CborValue::Array(cose) = cose.as_ref() else {
            panic!("COSE_Sign1 must be an array");
        };
        let protected = cose[0].as_bytes().expect("protected headers");
        let unprotected = cose[1].as_map().expect("unprotected headers");
        assert!(unprotected.iter().any(|(label, chain)| {
            label
                .as_integer()
                .and_then(|value| i64::try_from(value).ok())
                == Some(33)
                && chain.as_array().is_some_and(|certificates| {
                    certificates.len() == 1 && certificates[0].as_bytes().is_some()
                })
        }));
        let payload = cose[2].as_bytes().expect("MSO payload");
        let signature = cose[3].as_bytes().expect("COSE signature");
        let sig_structure = CborValue::Array(vec![
            CborValue::Text("Signature1".into()),
            CborValue::Bytes(protected.clone()),
            CborValue::Bytes(Vec::new()),
            CborValue::Bytes(payload.clone()),
        ]);
        let jwk = signer.public_jwk();
        let x = URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().expect("x"))
            .expect("x base64url");
        let y = URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().expect("y"))
            .expect("y base64url");
        let point =
            EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
        let verifying_key = VerifyingKey::from_encoded_point(&point).expect("issuer key");
        verifying_key
            .verify(
                &cbor_encode(&sig_structure).expect("Sig_structure"),
                &Signature::from_slice(signature).expect("raw ES256 signature"),
            )
            .expect("COSE signature verifies");
    }
}
