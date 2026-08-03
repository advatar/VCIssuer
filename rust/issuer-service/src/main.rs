#![forbid(unsafe_code)]

mod activechain_schema;
mod hybrid_codec;
#[cfg(target_os = "macos")]
mod hybrid_signer;
mod pq_backend;
#[cfg(target_os = "macos")]
mod signer;
mod svipe;

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::Path,
    extract::{Form, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::Redirect,
    routing::{get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ciborium::value::Value as CborValue;
use issuer_core::{
    Authorization, CredentialFormat, CredentialProfile, CredentialProof, DatasetId, Evidence,
    Instant, IssuerRole, KeyThumbprint, NonceId, Powers, ProfileId, Request, RequestId, Session,
    SessionId, SubjectEvidence, SubjectId, TokenBinding, WalletEvidence, authorize_sign,
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
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::info;
use url::Url;
use uuid::Uuid;

#[cfg(target_os = "macos")]
use hybrid_signer::HybridCredentialSigner;
#[cfg(target_os = "macos")]
use signer::KeychainSigner;

const PID_SD_JWT: &str = "eu.europa.ec.eudi.pid_vc_sd_jwt.de";
const PID_MDOC: &str = "eu.europa.ec.eudi.pid_mso_mdoc.de";
const EAA_MDOC: &str = "org.iso.18013.5.1.mDL.de";
const QEAA_SD_JWT: &str = "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt:de";
const QEAA_PID_BOUND_SD_JWT: &str =
    "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt:de:pid-bound";
const PID_VCT: &str = "eu.europa.ec.eudi.pid.1";
const DEV_SVIPE_PID_SD_JWT: &str = svipe::PROFILE;
const TLSN_EVIDENCE_SD_JWT: &str = "dev.advatar.tlsn.evidence.sd-jwt";
const TLSN_EVIDENCE_VCT: &str = "dev.advatar.tlsn.evidence.1";
const HYBRID_PQ_SD_JWT: &str = "dev.advatar.hybrid-pq.sd-jwt.v1";
const TLSN_ARTIFACT_VERSION: &str = "tlsn.notary-artifact.v1";
const MAX_TLSN_ARTIFACT_BYTES: usize = 256 * 1024;
const TLSN_EVIDENCE_LIFETIME_SECONDS: u64 = 300;

#[derive(Clone)]
struct AppState {
    issuer: Url,
    trusted_notary_key: Vec<u8>,
    hybrid_pq_enabled: bool,
    inner: Arc<Mutex<VolatileState>>,
    #[cfg(target_os = "macos")]
    metadata_signer: Arc<KeychainSigner>,
    #[cfg(target_os = "macos")]
    credential_signers: Arc<HashMap<&'static str, KeychainSigner>>,
    #[cfg(target_os = "macos")]
    hybrid_credential_signer: Option<Arc<HybridCredentialSigner>>,
    #[cfg(target_os = "macos")]
    development_signing_chains: Arc<HashMap<&'static str, Vec<Vec<u8>>>>,
}

#[derive(Default)]
struct VolatileState {
    pushed: HashMap<String, PushedAuthorization>,
    codes: HashMap<String, AuthorizationCode>,
    tokens: HashMap<String, AccessToken>,
    nonces: HashMap<String, bool>,
    dpop_jtis: HashSet<String>,
    binding_jtis: HashSet<String>,
    offers: HashMap<String, CredentialOffer>,
    tlsn_sessions: HashSet<String>,
}

#[derive(Clone)]
struct PushedAuthorization {
    client_id: String,
    redirect_uri: Url,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    tlsn_evidence: Option<VerifiedTlsnEvidence>,
}

struct AuthorizationCode {
    client_id: String,
    redirect_uri: Url,
    scope: String,
    code_challenge: String,
    consumed: bool,
    tlsn_evidence: Option<VerifiedTlsnEvidence>,
}

struct AccessToken {
    scope: String,
    dpop_jkt: String,
    tlsn_evidence: Option<VerifiedTlsnEvidence>,
}

struct CredentialOffer {
    profile: String,
    issuer_state: String,
    expires_at: u64,
    tlsn_evidence: Option<VerifiedTlsnEvidence>,
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
    issuer_state: Option<String>,
}

#[derive(Deserialize)]
struct CreateOfferRequest {
    credential_configuration_id: String,
}

#[derive(Serialize)]
struct CreateOfferResponse {
    credential_offer_uri: String,
    deep_link: String,
    expires_in: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsnEvidenceOfferRequest {
    artifact: SignedTlsnArtifact,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedTlsnArtifact {
    payload: TlsnArtifactPayload,
    algorithm: String,
    public_key: String,
    signature: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TlsnArtifactPayload {
    version: String,
    session_id: String,
    issued_at: u64,
    verifier_output: Value,
}

#[derive(Clone)]
struct VerifiedTlsnEvidence {
    session_id: String,
    issued_at: u64,
    verifier_output: Value,
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
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    credential_configuration_id: String,
    proofs: CredentialProofs,
    pid_binding: Option<PidBindingObject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialProofs {
    jwt: Vec<String>,
}

fn single_credential_proof(proofs: &CredentialProofs) -> Option<&str> {
    let [proof] = proofs.jwt.as_slice() else {
        return None;
    };
    Some(proof)
}

#[derive(Deserialize)]
struct PidBindingObject {
    pid_vp: String,
    proof_jwt: String,
}

#[derive(Deserialize)]
struct BindingProofClaims {
    aud: String,
    iat: u64,
    nonce: String,
    jti: String,
    pid_sd_hash: String,
    new_holder_jkt: String,
}

struct VerifiedPidBinding {
    subject: SubjectId,
    jti: String,
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
    let trusted_notary_key = std::env::var("TLSN_TRUSTED_NOTARY_KEY")
        .expect("TLSN_TRUSTED_NOTARY_KEY must contain the hex SEC1 P-256 notary public key");
    let trusted_notary_key =
        hex::decode(trusted_notary_key).expect("TLSN_TRUSTED_NOTARY_KEY must be valid hex");
    VerifyingKey::from_sec1_bytes(&trusted_notary_key)
        .expect("TLSN_TRUSTED_NOTARY_KEY must be a SEC1 P-256 public key");
    let address: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .expect("LISTEN_ADDR must be a socket address");
    let hybrid_pq_enabled = std::env::var("ENABLE_EXPERIMENTAL_HYBRID_PQ")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));

    #[cfg(target_os = "macos")]
    let credential_signers = [
        PID_SD_JWT,
        PID_MDOC,
        EAA_MDOC,
        QEAA_SD_JWT,
        QEAA_PID_BOUND_SD_JWT,
        DEV_SVIPE_PID_SD_JWT,
        TLSN_EVIDENCE_SD_JWT,
    ]
    .into_iter()
    .map(|profile| {
        let label = format!("dev.advatar.vcissuer.{}", key_label(profile));
        KeychainSigner::find_or_create(&label).map_or_else(
            |error| panic!("credential signing key {label} is unavailable: {error}"),
            |signer| (profile, signer),
        )
    })
    .collect();

    #[cfg(target_os = "macos")]
    let development_signing_chains = HashMap::from([(
        TLSN_EVIDENCE_SD_JWT,
        KeychainSigner::development_certificate_chain(
            "dev.advatar.vcissuer.development-attestation-ca",
            &format!("dev.advatar.vcissuer.{}", key_label(TLSN_EVIDENCE_SD_JWT)),
            issuer.as_str(),
        )
        .expect("TLSNotary development signing certificate chain must be available"),
    )]);

    #[cfg(target_os = "macos")]
    let hybrid_credential_signer = hybrid_pq_enabled.then(|| {
        Arc::new(
            HybridCredentialSigner::find_or_create("dev.advatar.vcissuer.hybrid-pq.es256.v1")
                .expect("experimental hybrid credential signer must be available"),
        )
    });

    let app = app(AppState {
        issuer,
        trusted_notary_key,
        hybrid_pq_enabled,
        inner: Arc::new(Mutex::new(VolatileState::default())),
        #[cfg(target_os = "macos")]
        metadata_signer: Arc::new(
            KeychainSigner::find_or_create("dev.advatar.vcissuer.metadata")
                .expect("metadata signing key must be available in macOS Keychain"),
        ),
        #[cfg(target_os = "macos")]
        credential_signers: Arc::new(credential_signers),
        #[cfg(target_os = "macos")]
        hybrid_credential_signer,
        #[cfg(target_os = "macos")]
        development_signing_chains: Arc::new(development_signing_chains),
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
    let configured_origins: HashSet<String> = std::env::var("CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    let ui_origins = AllowOrigin::predicate(move |origin: &HeaderValue, _| {
        let Ok(value) = origin.to_str() else {
            return false;
        };
        configured_origins.contains(value)
            || Url::parse(value).ok().is_some_and(|url| {
                matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
                    || (url.scheme() == "https"
                        && url
                            .host_str()
                            .is_some_and(|host| host.ends_with(".lovable.app")))
            })
    });

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
        .route(
            "/experimental/hybrid-pq/profile",
            get(hybrid_pq_profile_document),
        )
        .route(
            "/credential-signing-certificates/{configuration_id}",
            get(credential_signing_certificates),
        )
        .route("/credential-offers", post(create_credential_offer))
        .route(
            "/evidence-offers/tlsnotary",
            post(create_tlsn_evidence_offer),
        )
        .route("/credential-offer/{id}", get(get_credential_offer))
        .route("/par", post(par))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/nonce", post(nonce))
        .route("/credential", post(credential))
        .layer(
            CorsLayer::new()
                .allow_origin(ui_origins)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE]),
        )
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
    let tlsn_profile = tlsn_metadata_profile(issuer);
    let mut metadata = json!({
        "credential_issuer": issuer,
        "authorization_servers": [issuer],
        "credential_endpoint": format!("{issuer}/credential"),
        "nonce_endpoint": format!("{issuer}/nonce"),
        "batch_credential_issuance": {"batch_size": 1},
        "credential_configurations_supported": {
            PID_SD_JWT: sd_jwt_profile(PID_SD_JWT, "eu.europa.ec.eudi.pid.1", "German PID (SD-JWT VC)"),
            PID_MDOC: mdoc_profile(PID_MDOC, "eu.europa.ec.eudi.pid.1", "German PID (mdoc)"),
            EAA_MDOC: mdoc_profile(EAA_MDOC, "org.iso.18013.5.1.mDL", "German driving licence EAA (mdoc)"),
            QEAA_SD_JWT: learning_profile(QEAA_SD_JWT, "German learning QEAA (independently identified)", false),
            QEAA_PID_BOUND_SD_JWT: learning_profile(QEAA_PID_BOUND_SD_JWT, "German learning QEAA (cryptographically bound to PID)", true)
            ,DEV_SVIPE_PID_SD_JWT: sd_jwt_profile(DEV_SVIPE_PID_SD_JWT, "dev.eu.europa.ec.eudi.pid.1", "Development PID (Svipe proofing only)"),
            TLSN_EVIDENCE_SD_JWT: tlsn_profile
        }
    });
    if state.hybrid_pq_enabled {
        metadata["credential_configurations_supported"]
            .as_object_mut()
            .expect("credential configurations are an object")
            .insert(HYBRID_PQ_SD_JWT.into(), hybrid_metadata_profile(issuer));
    }
    metadata
}

fn hybrid_metadata_profile(issuer: &str) -> Value {
    json!({
        "format": hybrid_codec::FORMAT,
        "scope": HYBRID_PQ_SD_JWT,
        "vct": "dev.advatar.hybrid-pq.credential.v1",
        "cryptographic_binding_methods_supported": ["jwk"],
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
        },
        "experimental_profile": hybrid_codec::PROFILE,
        "experimental_profile_document": format!("{issuer}/experimental/hybrid-pq/profile"),
        "credential_wrapper_schema": "HybridCredentialWrapperV1",
        "shared_vectors_status": "complete-component-and-wrapper-corpora",
        "development_only": true,
        "eudi_conformant": false,
        "display": [{
            "name": "Experimental hybrid-PQ credential (non-EUDI)",
            "locale": "en"
        }]
    })
}

fn tlsn_metadata_profile(issuer: &str) -> Value {
    let mut tlsn_profile = sd_jwt_profile(
        TLSN_EVIDENCE_SD_JWT,
        TLSN_EVIDENCE_VCT,
        "TLSNotary web evidence (development)",
    );
    tlsn_profile
        .as_object_mut()
        .expect("profile is an object")
        .insert(
            "credential_signing_certificate_endpoint".into(),
            json!(format!(
                "{issuer}/credential-signing-certificates/{TLSN_EVIDENCE_SD_JWT}"
            )),
        );
    tlsn_profile
}

#[cfg(target_os = "macos")]
async fn credential_signing_certificates(
    State(state): State<AppState>,
    Path(configuration_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let chain = state
        .development_signing_chains
        .get(configuration_id.as_str())
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!({
        "credential_configuration_id": configuration_id,
        "x5c": chain.iter().map(|der| STANDARD.encode(der)).collect::<Vec<_>>(),
        "development_only": true
    })))
}

#[cfg(not(target_os = "macos"))]
async fn credential_signing_certificates(Path(_configuration_id): Path<String>) -> StatusCode {
    StatusCode::NOT_FOUND
}

fn learning_profile(configuration_id: &str, name: &str, pid_bound: bool) -> Value {
    let mut value = sd_jwt_profile(
        configuration_id,
        "urn:eu.europa.ec.eudi:learning:credential:1",
        name,
    );
    value.as_object_mut().expect("profile is an object").insert(
        "pid_binding".into(),
        if pid_bound {
            json!({
                "required": true,
                "pid_vct": PID_VCT,
                "presentation_format": "dc+sd-jwt",
                "binding_proof_alg_values_supported": ["ES256"]
            })
        } else {
            json!({"required": false})
        },
    );
    value
}

fn sd_jwt_profile(configuration_id: &str, vct: &str, name: &str) -> Value {
    let mut profile = json!({
        "format": "dc+sd-jwt",
        "scope": configuration_id,
        "vct": vct,
        "cryptographic_binding_methods_supported": ["jwk"],
        "credential_signing_alg_values_supported": ["ES256"],
        "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
        "display": [{"name": name, "locale": "de-DE"}]
    });
    if let Some(schema) = activechain_schema::pinned_schema_id(configuration_id) {
        profile
            .as_object_mut()
            .expect("profile is an object")
            .insert(
                "activechain_schema_id_v1".into(),
                Value::String(hex::encode(schema)),
            );
    }
    profile
}

fn mdoc_profile(configuration_id: &str, doc_type: &str, name: &str) -> Value {
    let mut profile = json!({
        "format": "mso_mdoc",
        "scope": configuration_id,
        "doctype": doc_type,
        "cryptographic_binding_methods_supported": ["cose_key"],
        "credential_signing_alg_values_supported": ["ES256"],
        "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
        "display": [{"name": name, "locale": "de-DE"}]
    });
    if let Some(schema) = activechain_schema::pinned_schema_id(configuration_id) {
        profile
            .as_object_mut()
            .expect("profile is an object")
            .insert(
                "activechain_schema_id_v1".into(),
                Value::String(hex::encode(schema)),
            );
    }
    profile
}

async fn oauth_metadata(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.issuer.as_str().trim_end_matches('/');
    Json(oauth_metadata_value(issuer))
}

fn oauth_metadata_value(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "require_pushed_authorization_requests": true,
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"]
    })
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

#[cfg(target_os = "macos")]
async fn hybrid_pq_profile_document(
    State(state): State<AppState>,
) -> Result<Json<Value>, StatusCode> {
    let signer = state
        .hybrid_credential_signer
        .as_ref()
        .filter(|_| state.hybrid_pq_enabled)
        .ok_or(StatusCode::NOT_FOUND)?;
    let public_key_envelope = hybrid_codec::encode_public_key_envelope(
        signer.classical_public_key(),
        signer.pq_public_key(),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({
        "version": hybrid_codec::VERSION,
        "profile": hybrid_codec::PROFILE,
        "purpose": hybrid_codec::PURPOSE,
        "credential_format": hybrid_codec::FORMAT,
        "configuration_id": HYBRID_PQ_SD_JWT,
        "acceptance_rule": "ES256 valid AND ML-DSA-65 valid",
        "logical_key_generation": signer.generation(),
        "classical": {
            "algorithm": "ES256",
            "kid": signer.classical_kid(),
            "public_key_sec1": URL_SAFE_NO_PAD.encode(signer.classical_public_key())
        },
        "post_quantum": {
            "algorithm": "ML-DSA-65",
            "kid": signer.pq_kid(),
            "public_key": URL_SAFE_NO_PAD.encode(signer.pq_public_key())
        },
        "public_key_envelope": URL_SAFE_NO_PAD.encode(public_key_envelope),
        "component_envelope_schema": "euwallet-pr103-frozen",
        "credential_wrapper_schema": "HybridCredentialWrapperV1",
        "development_only": true,
        "eudi_conformant": false,
        "shared_vectors_status": "complete-component-and-wrapper-corpora",
        "verification_report": "docs/hybrid-pq-verification-report.md"
    })))
}

#[cfg(not(target_os = "macos"))]
async fn hybrid_pq_profile_document() -> StatusCode {
    StatusCode::NOT_FOUND
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
    if !valid_scope(&request.scope, state.hybrid_pq_enabled) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope contains an unsupported credential",
        ));
    }
    let mut tlsn_evidence = None;
    if let Some(issuer_state) = request.issuer_state.as_deref() {
        let now = unix_time()?;
        let inner = state.inner.lock().await;
        let offer = inner
            .offers
            .values()
            .find(|offer| offer.issuer_state == issuer_state)
            .ok_or_else(|| {
                oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "issuer_state is unknown",
                )
            })?;
        if offer.expires_at < now
            || !request
                .scope
                .split_ascii_whitespace()
                .any(|scope| scope == offer.profile)
        {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "credential offer is expired or does not match the requested scope",
            ));
        }
        tlsn_evidence = offer.tlsn_evidence.clone();
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
            tlsn_evidence,
        },
    );
    Ok(Json(ParResponse {
        request_uri,
        expires_in: 60,
    }))
}

async fn create_credential_offer(
    State(state): State<AppState>,
    Json(request): Json<CreateOfferRequest>,
) -> Result<Json<CreateOfferResponse>, (StatusCode, Json<OAuthError>)> {
    if request.credential_configuration_id == TLSN_EVIDENCE_SD_JWT {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "TLSNotary evidence offers require verified evidence",
        ));
    }
    if !valid_scope(
        &request.credential_configuration_id,
        state.hybrid_pq_enabled,
    ) || request.credential_configuration_id.contains(' ')
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "credential configuration is unknown",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let issuer_state = random_token();
    let expires_in = 300;
    let expires_at = unix_time()?.saturating_add(expires_in);
    state.inner.lock().await.offers.insert(
        id.clone(),
        CredentialOffer {
            profile: request.credential_configuration_id,
            issuer_state,
            expires_at,
            tlsn_evidence: None,
        },
    );
    let credential_offer_uri = state
        .issuer
        .join(&format!("credential-offer/{id}"))
        .expect("opaque offer ID creates a valid URL")
        .to_string();
    let mut deep_link = Url::parse("openid-credential-offer://").expect("static URL is valid");
    deep_link
        .query_pairs_mut()
        .append_pair("credential_offer_uri", &credential_offer_uri);
    Ok(Json(CreateOfferResponse {
        credential_offer_uri,
        deep_link: deep_link.to_string(),
        expires_in,
    }))
}

async fn create_tlsn_evidence_offer(
    State(state): State<AppState>,
    Json(request): Json<TlsnEvidenceOfferRequest>,
) -> Result<Json<CreateOfferResponse>, (StatusCode, Json<OAuthError>)> {
    let now = unix_time()?;
    let evidence = verify_tlsn_artifact(&request.artifact, &state.trusted_notary_key, now)?;
    let id = Uuid::new_v4().to_string();
    let issuer_state = random_token();
    let expires_in = TLSN_EVIDENCE_LIFETIME_SECONDS;
    let expires_at = now.saturating_add(expires_in);
    let mut inner = state.inner.lock().await;
    reserve_tlsn_session(&mut inner.tlsn_sessions, &evidence.session_id)?;
    inner.offers.insert(
        id.clone(),
        CredentialOffer {
            profile: TLSN_EVIDENCE_SD_JWT.into(),
            issuer_state,
            expires_at,
            tlsn_evidence: Some(evidence),
        },
    );
    drop(inner);
    let credential_offer_uri = state
        .issuer
        .join(&format!("credential-offer/{id}"))
        .expect("opaque offer ID creates a valid URL")
        .to_string();
    let mut deep_link = Url::parse("openid-credential-offer://").expect("static URL is valid");
    deep_link
        .query_pairs_mut()
        .append_pair("credential_offer_uri", &credential_offer_uri);
    Ok(Json(CreateOfferResponse {
        credential_offer_uri,
        deep_link: deep_link.to_string(),
        expires_in,
    }))
}

async fn get_credential_offer(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<OAuthError>)> {
    let now = unix_time()?;
    let inner = state.inner.lock().await;
    let offer = inner.offers.get(&id).ok_or_else(|| {
        oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "credential offer is unknown",
        )
    })?;
    if offer.expires_at < now {
        return Err(oauth_error(
            StatusCode::GONE,
            "invalid_request",
            "credential offer has expired",
        ));
    }
    Ok(Json(json!({
        "credential_issuer": state.issuer.as_str().trim_end_matches('/'),
        "credential_configuration_ids": [offer.profile],
        "grants": {
            "authorization_code": {
                "issuer_state": offer.issuer_state
            }
        }
    })))
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
            tlsn_evidence: pushed.tlsn_evidence,
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
    let tlsn_evidence = code.tlsn_evidence.clone();
    let access_token = random_token();
    inner.tokens.insert(
        access_token.clone(),
        AccessToken {
            scope: scope.clone(),
            dpop_jkt: verified_dpop.jkt,
            tlsn_evidence,
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
    let nonce = random_credential_nonce();
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
    let credential_proof = single_credential_proof(&request.proofs).ok_or_else(|| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "exactly one JWT credential proof is required",
        )
    })?;
    let verified_proof = verify_credential_proof(credential_proof, &state.issuer)?;
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
    let nonce_used = inner.nonces.get(&verified_proof.nonce).ok_or_else(|| {
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
    let tlsn_evidence = access.tlsn_evidence.clone();
    if request.credential_configuration_id == TLSN_EVIDENCE_SD_JWT && tlsn_evidence.is_none() {
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "credential_request_denied",
            "TLSNotary evidence was not bound to this authorization",
        ));
    }
    let pid_binding = match request.credential_configuration_id.as_str() {
        QEAA_PID_BOUND_SD_JWT => {
            let supplied = request.pid_binding.as_ref().ok_or_else(|| {
                oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "the PID-bound profile requires pid_binding evidence",
                )
            })?;
            #[cfg(target_os = "macos")]
            let verified = verify_pid_binding(
                supplied,
                state
                    .credential_signers
                    .get(PID_SD_JWT)
                    .expect("PID signer is configured")
                    .public_jwk(),
                &state.issuer,
                &verified_proof.nonce,
                &verified_proof.holder_jkt,
                now,
            )?;
            #[cfg(not(target_os = "macos"))]
            return Err(oauth_error(
                StatusCode::NOT_IMPLEMENTED,
                "credential_request_denied",
                "PID presentation verification requires the configured issuer key",
            ));
            if !inner.binding_jtis.insert(verified.jti.clone()) {
                return Err(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "PID binding proof jti has already been used",
                ));
            }
            Some(verified)
        }
        _ if request.pid_binding.is_some() => {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "pid_binding evidence is not accepted by this credential profile",
            ));
        }
        _ => None,
    };
    authorize_kernel(
        &request.credential_configuration_id,
        &verified_proof.holder_jkt,
        &verified_proof.nonce,
        pid_binding.as_ref().map(|binding| binding.subject),
        now,
    )?;
    *inner
        .nonces
        .get_mut(&verified_proof.nonce)
        .expect("nonce was checked above") = true;
    drop(inner);

    match request.credential_configuration_id.as_str() {
        PID_SD_JWT | QEAA_SD_JWT | QEAA_PID_BOUND_SD_JWT | TLSN_EVIDENCE_SD_JWT => {
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
                    tlsn_evidence.as_ref(),
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
        HYBRID_PQ_SD_JWT => {
            #[cfg(target_os = "macos")]
            {
                let signer = state
                    .hybrid_credential_signer
                    .as_ref()
                    .filter(|_| state.hybrid_pq_enabled)
                    .ok_or_else(|| {
                        oauth_error(
                            StatusCode::FORBIDDEN,
                            "credential_request_denied",
                            "experimental hybrid-PQ issuance is disabled",
                        )
                    })?;
                let credential = issue_hybrid_credential(
                    signer,
                    &state.issuer,
                    &verified_proof.holder_jwk,
                    &verified_proof.holder_jkt,
                    &verified_proof.nonce,
                    now,
                )?;
                Ok(Json(json!({
                    "credentials": [{
                        "credential": URL_SAFE_NO_PAD.encode(credential),
                        "format": hybrid_codec::FORMAT
                    }]
                })))
            }
            #[cfg(not(target_os = "macos"))]
            Err(oauth_error(
                StatusCode::NOT_IMPLEMENTED,
                "credential_request_denied",
                "experimental hybrid-PQ issuance requires macOS Keychain",
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

fn valid_scope(scope: &str, hybrid_pq_enabled: bool) -> bool {
    let allowed = [
        PID_SD_JWT,
        PID_MDOC,
        EAA_MDOC,
        QEAA_SD_JWT,
        QEAA_PID_BOUND_SD_JWT,
        DEV_SVIPE_PID_SD_JWT,
        TLSN_EVIDENCE_SD_JWT,
    ];
    let mut count = 0;
    for item in scope.split_ascii_whitespace() {
        count += 1;
        if !(allowed.contains(&item) || hybrid_pq_enabled && item == HYBRID_PQ_SD_JWT) {
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
        QEAA_PID_BOUND_SD_JWT => "qeaa-pid-bound-sd-jwt",
        DEV_SVIPE_PID_SD_JWT => "svipe-pid-sd-jwt",
        TLSN_EVIDENCE_SD_JWT => "tlsn-evidence-sd-jwt",
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

fn random_credential_nonce() -> String {
    loop {
        let value = rand::rng().next_u64();
        if value != 0 {
            return value.to_string();
        }
    }
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

#[allow(clippy::too_many_lines)]
fn verify_pid_binding(
    binding: &PidBindingObject,
    trusted_pid_issuer_jwk: Value,
    issuer: &Url,
    expected_nonce: &str,
    expected_new_holder_jkt: &str,
    now: u64,
) -> Result<VerifiedPidBinding, (StatusCode, Json<OAuthError>)> {
    if binding.pid_vp.len() > 32_768 || binding.proof_jwt.len() > 8_192 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "PID binding evidence exceeds the accepted size",
        ));
    }
    let mut parts = binding.pid_vp.split('~');
    let issuer_jwt = parts.next().unwrap_or_default();
    let tail: Vec<&str> = parts.filter(|part| !part.is_empty()).collect();
    if issuer_jwt.is_empty() || tail.last().copied() != Some(binding.proof_jwt.as_str()) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "PID VP must end in the supplied cross-attestation proof JWT",
        ));
    }
    let trusted_jwk: EcJwk = serde_json::from_value(trusted_pid_issuer_jwk).map_err(|_| {
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "configured PID issuer key is malformed",
        )
    })?;
    let (issuer_key, _, _) = verifying_key_and_jwk(&trusted_jwk, "invalid_proof")?;
    let pid_payload = verify_jws_payload(issuer_jwt, &issuer_key, "PID credential")?;
    if pid_payload.get("vct").and_then(Value::as_str) != Some(PID_VCT) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "presented credential is not the required PID type",
        ));
    }
    if pid_payload
        .get("iss")
        .and_then(Value::as_str)
        .map(|value| value.trim_end_matches('/'))
        != Some(issuer.as_str().trim_end_matches('/'))
        || pid_payload
            .get("nbf")
            .and_then(Value::as_u64)
            .is_none_or(|nbf| nbf > now)
        || pid_payload
            .get("exp")
            .and_then(Value::as_u64)
            .is_none_or(|exp| now >= exp)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "presented PID issuer or validity interval is not accepted",
        ));
    }
    let allowed_disclosures: HashSet<&str> = pid_payload
        .get("_sd")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "PID has no selective-disclosure digests",
            )
        })?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let pid_holder_jwk: EcJwk =
        serde_json::from_value(pid_payload.pointer("/cnf/jwk").cloned().ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "PID has no holder key",
            )
        })?)
        .map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "PID holder key is malformed",
            )
        })?;
    let (pid_holder_key, _, _) = verifying_key_and_jwk(&pid_holder_jwk, "invalid_proof")?;
    let proof_payload =
        verify_jws_payload(&binding.proof_jwt, &pid_holder_key, "PID binding proof")?;
    let claims: BindingProofClaims = serde_json::from_value(proof_payload).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "PID binding proof claims are malformed",
        )
    })?;
    if claims.aud.trim_end_matches('/') != issuer.as_str().trim_end_matches('/')
        || claims.nonce != expected_nonce
        || claims.new_holder_jkt != expected_new_holder_jkt
        || claims.pid_sd_hash != URL_SAFE_NO_PAD.encode(Sha256::digest(issuer_jwt.as_bytes()))
        || claims.jti.is_empty()
        || claims.jti.len() > 256
        || claims.iat > now.saturating_add(5)
        || now.saturating_sub(claims.iat) > 300
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "PID binding proof is stale or does not bind this PID, nonce, issuer, and new holder key",
        ));
    }

    let mut family_name = None;
    let mut given_name = None;
    let mut birthdate = None;
    for encoded in tail.iter().take(tail.len().saturating_sub(1)) {
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
        if !allowed_disclosures.contains(digest.as_str()) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "PID disclosure is not committed by the issuer",
            ));
        }
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "PID disclosure is malformed",
            )
        })?;
        let disclosure: Value = serde_json::from_slice(&decoded).map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "PID disclosure is not JSON",
            )
        })?;
        let values = disclosure.as_array().ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "PID disclosure is not an array",
            )
        })?;
        if values.len() != 3 {
            continue;
        }
        match values[1].as_str() {
            Some("family_name") => family_name = values[2].as_str().map(str::to_owned),
            Some("given_name") => given_name = values[2].as_str().map(str::to_owned),
            Some("birthdate") => birthdate = values[2].as_str().map(str::to_owned),
            _ => {}
        }
    }
    if family_name.as_deref() != Some("Mustermann")
        || given_name.as_deref() != Some("Erika")
        || birthdate.as_deref() != Some("1990-01-01")
    {
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "credential_request_denied",
            "PID subject does not match the authoritative education record",
        ));
    }
    let canonical_subject = format!(
        "{}\u{1f}{}\u{1f}{}",
        family_name.expect("matched"),
        given_name.expect("matched"),
        birthdate.expect("matched")
    );
    Ok(VerifiedPidBinding {
        subject: SubjectId(hash_u128(&canonical_subject)),
        jti: claims.jti,
    })
}

fn verify_jws_payload(
    compact: &str,
    key: &VerifyingKey,
    label: &str,
) -> Result<Value, (StatusCode, Json<OAuthError>)> {
    let parts: Vec<&str> = compact.split('.').collect();
    if parts.len() != 3 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("{label} is not a compact JWS"),
        ));
    }
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .ok()
        .and_then(|raw| Signature::from_slice(&raw).ok())
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                format!("{label} signature is malformed"),
            )
        })?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                format!("{label} signature is invalid"),
            )
        })?;
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("{label} payload is malformed"),
        )
    })?;
    serde_json::from_slice(&payload).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("{label} payload is not JSON"),
        )
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

fn verify_tlsn_artifact(
    artifact: &SignedTlsnArtifact,
    trusted_key: &[u8],
    now: u64,
) -> Result<VerifiedTlsnEvidence, (StatusCode, Json<OAuthError>)> {
    if artifact.payload.version != TLSN_ARTIFACT_VERSION || artifact.algorithm != "ES256" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_evidence",
            "unsupported TLSNotary artifact version or algorithm",
        ));
    }
    if artifact.payload.session_id.is_empty()
        || artifact.payload.session_id.len() > 256
        || artifact.payload.issued_at > now.saturating_add(5)
        || now.saturating_sub(artifact.payload.issued_at) > TLSN_EVIDENCE_LIFETIME_SECONDS
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_evidence",
            "TLSNotary artifact is stale, future-dated, or has an invalid session identifier",
        ));
    }
    let message = serde_json::to_vec(&artifact.payload).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_evidence",
            "TLSNotary artifact payload cannot be encoded",
        )
    })?;
    if message.len() > MAX_TLSN_ARTIFACT_BYTES {
        return Err(oauth_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_evidence",
            "TLSNotary artifact exceeds the accepted size",
        ));
    }
    let embedded_key = URL_SAFE_NO_PAD.decode(&artifact.public_key).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_evidence",
            "TLSNotary public key is malformed",
        )
    })?;
    if embedded_key.as_slice().ct_eq(trusted_key).unwrap_u8() != 1 {
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "invalid_evidence",
            "TLSNotary artifact was not signed by the configured notary",
        ));
    }
    let signature = URL_SAFE_NO_PAD.decode(&artifact.signature).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_evidence",
            "TLSNotary signature is malformed",
        )
    })?;
    let signature = Signature::from_slice(&signature).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_evidence",
            "TLSNotary signature has an invalid length",
        )
    })?;
    let key = VerifyingKey::from_sec1_bytes(trusted_key).map_err(|_| {
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "configured TLSNotary key is invalid",
        )
    })?;
    key.verify(&message, &signature).map_err(|_| {
        oauth_error(
            StatusCode::FORBIDDEN,
            "invalid_evidence",
            "TLSNotary artifact signature verification failed",
        )
    })?;
    Ok(VerifiedTlsnEvidence {
        session_id: artifact.payload.session_id.clone(),
        issued_at: artifact.payload.issued_at,
        verifier_output: artifact.payload.verifier_output.clone(),
    })
}

fn reserve_tlsn_session(
    sessions: &mut HashSet<String>,
    session_id: &str,
) -> Result<(), (StatusCode, Json<OAuthError>)> {
    if sessions.insert(session_id.to_owned()) {
        Ok(())
    } else {
        Err(oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "TLSNotary session has already created an issuance offer",
        ))
    }
}

#[allow(clippy::too_many_lines)]
fn authorize_kernel(
    profile_name: &str,
    holder_jkt: &str,
    nonce: &str,
    pid_subject: Option<SubjectId>,
    now: u64,
) -> Result<(), (StatusCode, Json<OAuthError>)> {
    let role = match profile_name {
        PID_SD_JWT | PID_MDOC => IssuerRole::Pid,
        QEAA_SD_JWT | QEAA_PID_BOUND_SD_JWT | DEV_SVIPE_PID_SD_JWT => IssuerRole::Qeaa,
        EAA_MDOC => IssuerRole::NonQualifiedEaa,
        TLSN_EVIDENCE_SD_JWT | HYBRID_PQ_SD_JWT => IssuerRole::DevelopmentEvidence,
        _ => {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "unknown_credential_configuration",
                "credential configuration is unknown",
            ));
        }
    };
    let format = match profile_name {
        PID_SD_JWT
        | QEAA_SD_JWT
        | QEAA_PID_BOUND_SD_JWT
        | DEV_SVIPE_PID_SD_JWT
        | TLSN_EVIDENCE_SD_JWT
        | HYBRID_PQ_SD_JWT => CredentialFormat::SdJwtVc,
        PID_MDOC | EAA_MDOC => CredentialFormat::Mdoc,
        _ => unreachable!("profile was checked above"),
    };
    let profile_id = ProfileId(hash_u128(profile_name));
    let holder_key = KeyThumbprint(hash_u128(holder_jkt));
    let nonce_id = NonceId(hash_u128(nonce));
    if profile_name == QEAA_PID_BOUND_SD_JWT && pid_subject.is_none() {
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "credential_request_denied",
            "PID-bound issuance has no verified PID subject",
        ));
    }
    let subject = pid_subject.unwrap_or_else(|| SubjectId(hash_u128("demo-education-subject")));
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
        pid_binding_required: profile_name == QEAA_PID_BOUND_SD_JWT,
        // This service path issues ordinary (non-mandate) credentials, so it does not require the
        // isolated hybrid-PQ evidence gate. Mandate issuance goes through a distinct encoder (D4).
        require_hybrid_pq: false,
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
        // Ignored for non-`Representation` roles; empty here.
        requested_powers: Powers(0),
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
            pid_binding_verified: pid_subject.is_some(),
        },
        expected_nonce: nonce_id,
        nonce_unused: true,
        issuer_entitled: true,
        status_reserved: true,
        already_issued: false,
        wia_ka_maintenance_end: Instant(now.saturating_add(86_400)),
        hybrid_pq_bound: false,
        delegation: None,
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
fn issue_hybrid_credential(
    signer: &HybridCredentialSigner,
    issuer: &Url,
    holder_jwk: &Value,
    holder_jkt: &str,
    nonce: &str,
    now: u64,
) -> Result<Vec<u8>, (StatusCode, Json<OAuthError>)> {
    let claims = [
        ("credential_name", json!("Experimental hybrid credential")),
        ("assurance", json!("development-only-non-eudi")),
        ("issuing_country", json!("DE")),
    ];
    let mut disclosures = Vec::with_capacity(claims.len());
    let mut disclosure_hashes = Vec::with_capacity(claims.len());
    for (name, value) in claims {
        let disclosure = CborValue::Array(vec![
            CborValue::Text(random_token()),
            CborValue::Text(name.into()),
            CborValue::Bytes(
                serde_json::to_vec(&value).expect("development claim is serializable"),
            ),
        ]);
        let disclosure = encode_canonical_cbor(&disclosure)?;
        disclosure_hashes.push(CborValue::Bytes(Sha256::digest(&disclosure).to_vec()));
        disclosures.push(disclosure);
    }
    let payload = encode_canonical_cbor(&CborValue::Map(vec![
        cbor_pair(
            1,
            CborValue::Text(issuer.as_str().trim_end_matches('/').into()),
        ),
        cbor_pair(2, CborValue::Integer(now.into())),
        cbor_pair(3, CborValue::Integer(now.saturating_add(3600).into())),
        cbor_pair(
            4,
            CborValue::Text("dev.advatar.hybrid-pq.credential.v1".into()),
        ),
        cbor_pair(
            5,
            CborValue::Bytes(
                serde_json::to_vec(holder_jwk).expect("verified holder JWK is serializable"),
            ),
        ),
        cbor_pair(6, CborValue::Array(disclosure_hashes)),
        cbor_pair(7, CborValue::Bool(true)),
    ]))?;
    let issuer_identity = issuer.as_str().trim_end_matches('/').as_bytes().to_vec();
    let context = hybrid_codec::HybridContext {
        wallet_identity: holder_jkt.as_bytes().to_vec(),
        issuer_identity: Some(issuer_identity.clone()),
        key_generation: signer.generation(),
        transaction_id: Some(nonce.as_bytes().to_vec()),
        session_id: None,
        audience: Some(issuer_identity),
        nonce: Sha256::digest(nonce.as_bytes()).to_vec(),
        created_at_epoch_seconds: now,
        expires_at_epoch_seconds: now.saturating_add(3600),
        transcript_hash: None,
    };
    let unsigned = hybrid_codec::UnsignedEnvelope {
        purpose: hybrid_codec::HybridPurpose::TestSdJwtWrapperV1,
        context,
        payload,
        disclosures,
        classical_kid: signer.classical_kid().into(),
        pq_kid: signer.pq_kid().into(),
        generation: signer.generation(),
    };
    signer.sign_envelope(&unsigned).map_err(|error| {
        tracing::error!(%error, "experimental hybrid credential signing failed");
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "experimental hybrid credential signing is unavailable",
        )
    })
}

#[cfg(target_os = "macos")]
fn encode_canonical_cbor(value: &CborValue) -> Result<Vec<u8>, (StatusCode, Json<OAuthError>)> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).map_err(|_| {
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "experimental hybrid credential encoding failed",
        )
    })?;
    Ok(encoded)
}

#[cfg(target_os = "macos")]
fn cbor_pair(key: u64, value: CborValue) -> (CborValue, CborValue) {
    (CborValue::Integer(key.into()), value)
}

#[cfg(target_os = "macos")]
fn issue_sd_jwt(
    signer: &KeychainSigner,
    issuer: &Url,
    profile: &str,
    holder_jwk: &Value,
    now: u64,
    tlsn_evidence: Option<&VerifiedTlsnEvidence>,
) -> Result<String, (StatusCode, Json<OAuthError>)> {
    let (vct, claims) = match profile {
        PID_SD_JWT | DEV_SVIPE_PID_SD_JWT => (
            "eu.europa.ec.eudi.pid.1",
            vec![
                ("family_name", json!("Mustermann")),
                ("given_name", json!("Erika")),
                ("birthdate", json!("1990-01-01")),
                ("age_over_18", json!(true)),
                ("issuing_country", json!("DE")),
            ],
        ),
        QEAA_SD_JWT | QEAA_PID_BOUND_SD_JWT => (
            "urn:eu.europa.ec.eudi:learning:credential:1",
            vec![
                ("credential_name", json!("Hochschulabschluss")),
                ("awarding_body", json!("German Development University")),
                ("qualification", json!("Master of Science")),
                ("issuing_country", json!("DE")),
            ],
        ),
        TLSN_EVIDENCE_SD_JWT => {
            let evidence = tlsn_evidence.expect("TLSNotary profile checked evidence binding");
            (
                TLSN_EVIDENCE_VCT,
                vec![
                    ("tlsn_session_id", json!(evidence.session_id)),
                    ("tlsn_issued_at", json!(evidence.issued_at)),
                    ("tlsn_verifier_output", evidence.verifier_output.clone()),
                    ("assurance", json!("tlsnotary-development-evidence")),
                ],
            )
        }
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
    let mut payload = payload;
    if profile == QEAA_PID_BOUND_SD_JWT {
        payload
            .as_object_mut()
            .expect("payload is an object")
            .insert("cryptographically_bound_to".into(), json!(PID_VCT));
    }
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
    description: impl Into<String>,
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
        assert!(valid_scope(PID_SD_JWT, false));
        assert!(valid_scope(TLSN_EVIDENCE_SD_JWT, false));
        assert!(!valid_scope(HYBRID_PQ_SD_JWT, false));
        assert!(valid_scope(HYBRID_PQ_SD_JWT, true));
        assert!(!valid_scope("openid unknown", true));
        assert!(!valid_scope("", true));
    }

    #[test]
    fn tlsn_metadata_advertises_a_profile_bound_certificate_endpoint() {
        let profile = tlsn_metadata_profile("https://issuer.example");
        assert_eq!(profile["vct"], TLSN_EVIDENCE_VCT);
        assert_eq!(
            profile["credential_signing_certificate_endpoint"],
            "https://issuer.example/credential-signing-certificates/dev.advatar.tlsn.evidence.sd-jwt"
        );
    }

    #[test]
    fn hybrid_metadata_is_private_experimental_and_does_not_advertise_mldsa_as_standard() {
        let profile = hybrid_metadata_profile("https://issuer.example");
        assert_eq!(profile["format"], hybrid_codec::FORMAT);
        assert_eq!(profile["experimental_profile"], hybrid_codec::PROFILE);
        assert_eq!(profile["development_only"], true);
        assert_eq!(profile["eudi_conformant"], false);
        assert_eq!(
            profile["credential_wrapper_schema"],
            "HybridCredentialWrapperV1"
        );
        assert_eq!(
            profile["shared_vectors_status"],
            "complete-component-and-wrapper-corpora"
        );
        assert!(
            profile
                .get("credential_signing_alg_values_supported")
                .is_none()
        );
        assert_eq!(
            profile["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"],
            json!(["ES256"])
        );
    }

    #[test]
    fn authorization_server_metadata_advertises_mandatory_par() {
        let metadata = oauth_metadata_value("https://issuer.example");
        assert_eq!(metadata["require_pushed_authorization_requests"], true);
        assert_eq!(
            metadata["pushed_authorization_request_endpoint"],
            "https://issuer.example/par"
        );
    }

    #[test]
    fn credential_nonces_are_nonzero_canonical_decimal_u64_values() {
        let mut observed = HashSet::new();
        for _ in 0..128 {
            let nonce = random_credential_nonce();
            let parsed = nonce.parse::<u64>().expect("decimal u64 nonce");
            assert_ne!(parsed, 0);
            assert_eq!(parsed.to_string(), nonce);
            assert!(observed.insert(nonce));
        }
    }

    #[test]
    fn credential_request_accepts_only_the_final_single_jwt_proof_shape() {
        let valid: CredentialRequest = serde_json::from_value(json!({
            "credential_configuration_id": TLSN_EVIDENCE_SD_JWT,
            "proofs": {"jwt": ["header.payload.signature"]}
        }))
        .expect("final proof array shape");
        assert_eq!(valid.proofs.jwt, ["header.payload.signature"]);

        for invalid in [
            json!({
                "credential_configuration_id": TLSN_EVIDENCE_SD_JWT,
                "proofs": {"jwt": []}
            }),
            json!({
                "credential_configuration_id": TLSN_EVIDENCE_SD_JWT,
                "proofs": {"jwt": ["one", "two"]}
            }),
            json!({
                "credential_configuration_id": TLSN_EVIDENCE_SD_JWT,
                "proof": {"proof_type": "jwt", "jwt": "legacy"}
            }),
            json!({
                "credential_configuration_id": TLSN_EVIDENCE_SD_JWT,
                "proofs": {"jwt": ["proof"], "unexpected": []}
            }),
        ] {
            let parsed = serde_json::from_value::<CredentialRequest>(invalid);
            assert!(
                parsed
                    .as_ref()
                    .ok()
                    .and_then(|request| single_credential_proof(&request.proofs))
                    .is_none()
            );
        }
    }

    fn tlsn_artifact(key: &SigningKey, issued_at: u64) -> SignedTlsnArtifact {
        let payload = TlsnArtifactPayload {
            version: TLSN_ARTIFACT_VERSION.into(),
            session_id: "tlsn-session-1".into(),
            issued_at,
            verifier_output: json!({"serverName":"example.com","status":200}),
        };
        let signature: Signature =
            key.sign(&serde_json::to_vec(&payload).expect("artifact payload must serialize"));
        SignedTlsnArtifact {
            payload,
            algorithm: "ES256".into(),
            public_key: URL_SAFE_NO_PAD
                .encode(key.verifying_key().to_encoded_point(false).as_bytes()),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }

    #[test]
    fn tlsn_artifact_is_pinned_fresh_and_tamper_evident() {
        let now = unix_time().expect("clock");
        let key = SigningKey::from_slice(&[7; 32]).expect("test key");
        let trusted = key.verifying_key().to_encoded_point(false);
        let artifact = tlsn_artifact(&key, now);
        let verified =
            verify_tlsn_artifact(&artifact, trusted.as_bytes(), now).expect("valid artifact");
        assert_eq!(verified.session_id, "tlsn-session-1");

        let wrong = SigningKey::from_slice(&[9; 32]).expect("other test key");
        assert!(
            verify_tlsn_artifact(
                &artifact,
                wrong.verifying_key().to_encoded_point(false).as_bytes(),
                now
            )
            .is_err()
        );

        let mut tampered = artifact.clone();
        tampered.payload.verifier_output["status"] = json!(500);
        assert!(verify_tlsn_artifact(&tampered, trusted.as_bytes(), now).is_err());
        assert!(
            verify_tlsn_artifact(
                &tlsn_artifact(&key, now - TLSN_EVIDENCE_LIFETIME_SECONDS - 1),
                trusted.as_bytes(),
                now
            )
            .is_err()
        );
        assert!(
            verify_tlsn_artifact(&tlsn_artifact(&key, now + 6), trusted.as_bytes(), now).is_err()
        );
    }

    #[test]
    fn tlsn_profile_requires_evidence_bound_authorization() {
        let evidence = VerifiedTlsnEvidence {
            session_id: "session".into(),
            issued_at: 1,
            verifier_output: json!({"ok":true}),
        };
        let offer = CredentialOffer {
            profile: TLSN_EVIDENCE_SD_JWT.into(),
            issuer_state: "state".into(),
            expires_at: 2,
            tlsn_evidence: Some(evidence),
        };
        assert!(offer.tlsn_evidence.is_some());
        assert_eq!(offer.profile, TLSN_EVIDENCE_SD_JWT);

        let mut sessions = HashSet::new();
        reserve_tlsn_session(&mut sessions, "session").expect("first reservation");
        assert!(reserve_tlsn_session(&mut sessions, "session").is_err());
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

    fn public_jwk(key: &SigningKey) -> Value {
        let point = key.verifying_key().to_encoded_point(false);
        json!({
            "kty":"EC", "crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(point.x().expect("x")),
            "y":URL_SAFE_NO_PAD.encode(point.y().expect("y"))
        })
    }

    fn signed_jwt(key: &SigningKey, header: &Value, payload: &Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload"));
        let input = format!("{header}.{payload}");
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn pid_binding_verifies_identity_and_both_key_relationships() {
        let now = unix_time().expect("clock");
        let issuer_url = Url::parse("http://127.0.0.1:18080").expect("issuer");
        let issuer_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let pid_holder = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let new_holder = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let new_jwk: EcJwk = serde_json::from_value(public_jwk(&new_holder)).expect("jwk");
        let (_, new_jkt, _) = verifying_key_and_jwk(&new_jwk, "invalid_proof").expect("jkt");
        let disclosures: Vec<String> = [
            json!(["a", "family_name", "Mustermann"]),
            json!(["b", "given_name", "Erika"]),
            json!(["c", "birthdate", "1990-01-01"]),
        ]
        .into_iter()
        .map(|value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("disclosure")))
        .collect();
        let digests: Vec<String> = disclosures
            .iter()
            .map(|value| URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes())))
            .collect();
        let pid_jwt = signed_jwt(
            &issuer_key,
            &json!({"alg":"ES256","typ":"dc+sd-jwt"}),
            &json!({
                "iss":issuer_url.as_str().trim_end_matches('/'), "vct":PID_VCT,
                "nbf":now-1, "exp":now+300, "cnf":{"jwk":public_jwk(&pid_holder)},
                "_sd":digests
            }),
        );
        let proof = signed_jwt(
            &pid_holder,
            &json!({"alg":"ES256","typ":"eudi-pid-binding+jwt"}),
            &json!({
                "aud":issuer_url.as_str(), "iat":now, "nonce":"nonce", "jti":"binding-1",
                "pid_sd_hash":URL_SAFE_NO_PAD.encode(Sha256::digest(pid_jwt.as_bytes())),
                "new_holder_jkt":new_jkt
            }),
        );
        let binding = PidBindingObject {
            pid_vp: format!("{}~{}~{}", pid_jwt, disclosures.join("~"), proof),
            proof_jwt: proof,
        };
        let verified = verify_pid_binding(
            &binding,
            public_jwk(&issuer_key),
            &issuer_url,
            "nonce",
            &new_jkt,
            now,
        )
        .expect("valid PID binding");
        assert_eq!(verified.jti, "binding-1");

        assert!(
            verify_pid_binding(
                &binding,
                public_jwk(&issuer_key),
                &issuer_url,
                "nonce",
                "other-key",
                now,
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
