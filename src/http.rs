use crate::config::RVFAConfig;
use crate::storage;
use anyhow::Context;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fred::prelude::ClientLike;
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::Duration;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_scalar::{Scalar, Servable as ScalarServable};

#[derive(Clone)]
pub struct AppState {
    pub client: fred::clients::Client,
    pub blake3_key: [u8; 32],
}

pub async fn serve(config: &RVFAConfig, client: fred::clients::Client) -> anyhow::Result<()> {
    let blake3_key = config.blake3_key_bytes()?;
    let state = AppState { client, blake3_key };

    let address = SocketAddr::from((config.address, config.port));
    tracing::info!("HTTP server binding on {}", address);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind HTTP listener on {}", address))?;

    let router = build_router(state);

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server exited unexpectedly")
}

fn build_router(state: AppState) -> Router {
    let openapi = ApiDoc::openapi();

    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route(
            "/api/users/{sub}/tokens",
            get(list_tokens).post(create_token),
        )
        .route("/api/users/{sub}/tokens/{id}", delete(delete_token))
        .route("/forward-auth", get(forward_auth))
        .merge(Scalar::with_url("/docs", openapi))
        .layer(ConcurrencyLimitLayer::new(1024))
        .layer(TimeoutLayer::new(Duration::from_secs(15)))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

#[derive(OpenApi)]
#[openapi(
    paths(
        live,
        ready,
        list_tokens,
        create_token,
        delete_token,
        forward_auth
    ),
    components(
        schemas(
            ApiErrorBody,
            HealthStatus,
            TokenSummary,
            CreateTokenRequest,
            CreateTokenResponse
        )
    ),
    tags(
        (name = "health", description = "Health endpoints"),
        (name = "tokens", description = "API token management"),
        (name = "forward-auth", description = "Traefik forward auth compatibility")
    )
)]
struct ApiDoc;

#[derive(Debug, Serialize, ToSchema)]
struct ApiErrorBody {
    message: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: Cow<'static, str>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn internal(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ApiErrorBody {
            message: self.message.to_string(),
        });
        (self.status, body).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("internal error: {:?}", err);
        ApiError::internal("internal server error")
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct HealthStatus {
    status: &'static str,
}

#[utoipa::path(
    get,
    path = "/health/live",
    tag = "health",
    responses((status = 200, body = HealthStatus))
)]
async fn live() -> Json<HealthStatus> {
    Json(HealthStatus { status: "ok" })
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "health",
    responses(
        (status = 200, body = HealthStatus),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn ready(State(state): State<AppState>) -> Result<Json<HealthStatus>, ApiError> {
    state.client.ping::<String>(None).await.map_err(|err| {
        tracing::warn!("readiness ping failed: {:?}", err);
        ApiError::internal("redis unavailable")
    })?;

    Ok(Json(HealthStatus { status: "ready" }))
}

#[derive(Debug, Serialize, ToSchema)]
struct TokenSummary {
    id: String,
    description: Option<String>,
    created_at: String,
}

#[utoipa::path(
    get,
    path = "/api/users/{sub}/tokens",
    tag = "tokens",
    params(
        ("sub" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, body = [TokenSummary]),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn list_tokens(
    State(state): State<AppState>,
    Path(sub): Path<String>,
) -> Result<Json<Vec<TokenSummary>>, ApiError> {
    let tokens = storage::list_user_tokens(&state.client, &sub)
        .await
        .map_err(ApiError::from)?;

    let summaries = tokens
        .into_iter()
        .map(|token| TokenSummary {
            id: token.id,
            description: if token.description.is_empty() {
                None
            } else {
                Some(token.description)
            },
            created_at: token.created_at,
        })
        .collect();

    Ok(Json(summaries))
}

const MAX_DESCRIPTION_LENGTH: usize = 256;

#[derive(Debug, Deserialize, ToSchema)]
struct CreateTokenRequest {
    /// Optional description to help identify the token (max 256 characters).
    #[schema(max_length = 256)]
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct CreateTokenResponse {
    token: String,
    id: String,
    sub: String,
    description: Option<String>,
    created_at: String,
}

#[utoipa::path(
    post,
    path = "/api/users/{sub}/tokens",
    tag = "tokens",
    params(
        ("sub" = String, Path, description = "Subject identifier")
    ),
    request_body(
        content = CreateTokenRequest,
        description = "Optional description"
    ),
    responses(
        (status = 201, body = CreateTokenResponse),
        (status = 400, body = ApiErrorBody),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn create_token(
    State(state): State<AppState>,
    Path(raw_sub): Path<String>,
    Json(payload): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), ApiError> {
    if raw_sub.trim().is_empty() {
        return Err(ApiError::bad_request("subject must not be empty"));
    }

    const TOKEN_LENGTH: usize = 32; // 256 bits
    let raw_token = generate_token(TOKEN_LENGTH);
    let token_hash = hash_token(&raw_token, &state.blake3_key);
    let description = payload
        .description
        .map(|desc| desc.trim().to_string())
        .filter(|desc| !desc.is_empty())
        .unwrap_or_default();

    if description.len() > MAX_DESCRIPTION_LENGTH {
        return Err(ApiError::bad_request(format!(
            "description exceeds {} characters",
            MAX_DESCRIPTION_LENGTH
        )));
    }

    storage::create_api_token(&state.client, &raw_sub, &token_hash, &description)
        .await
        .map_err(ApiError::from)?;

    let created = storage::read_api_token(&state.client, &token_hash)
        .await
        .map_err(ApiError::from)?
        .context("stored token missing after creation")
        .map_err(ApiError::from)?;

    let storage::ApiToken {
        sub: stored_sub,
        description: stored_description,
        created_at,
    } = created;

    let response = CreateTokenResponse {
        token: raw_token,
        id: token_hash,
        sub: stored_sub,
        description: if stored_description.is_empty() {
            None
        } else {
            Some(stored_description)
        },
        created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    delete,
    path = "/api/users/{sub}/tokens/{id}",
    tag = "tokens",
    params(
        ("sub" = String, Path, description = "Subject identifier"),
        ("id" = String, Path, description = "Token identifier (hashed)")
    ),
    responses(
        (status = 204),
        (status = 404, body = ApiErrorBody),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn delete_token(
    State(state): State<AppState>,
    Path((sub, token_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let owner = storage::read_api_token_sub(&state.client, &token_id)
        .await
        .map_err(ApiError::from)?;

    match owner {
        Some(owner_sub) if owner_sub == sub => {
            let deleted = storage::delete_api_token(&state.client, &token_id)
                .await
                .map_err(ApiError::from)?;
            if deleted {
                Ok(StatusCode::NO_CONTENT)
            } else {
                Err(ApiError::not_found("token not found"))
            }
        }
        Some(_) => Err(ApiError::not_found("token not found")),
        None => Err(ApiError::not_found("token not found")),
    }
}

#[derive(Debug, Deserialize, IntoParams)]
struct ForwardAuthQuery {
    #[serde(default)]
    token: Option<String>,
}

#[utoipa::path(
    get,
    path = "/forward-auth",
    tag = "forward-auth",
    params(
        ForwardAuthQuery
    ),
    responses(
        (status = 204, description = "Token accepted"),
        (status = 401, body = ApiErrorBody)
    )
)]
async fn forward_auth(
    State(state): State<AppState>,
    Query(query): Query<ForwardAuthQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = extract_token(query.token.as_deref(), &headers)
        .ok_or_else(|| ApiError::unauthorized("missing token"))?;

    let token_hash = hash_token(&token, &state.blake3_key);
    let sub = storage::read_api_token_sub(&state.client, &token_hash)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::unauthorized("invalid token"))?;

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("X-Authenticated-User", sub.as_str())
        .header("X-Authenticated-Token-Id", token_hash.as_str())
        .body(Body::empty())
        .map_err(|_| ApiError::internal("failed to build response"))
}

fn extract_token(query_token: Option<&str>, headers: &HeaderMap) -> Option<String> {
    if let Some(token) = query_token.and_then(trim_non_empty) {
        return Some(token.to_owned());
    }

    if let Some(token) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_authorization)
    {
        return Some(token);
    }

    if let Some(token) = headers
        .get("X-API-Token")
        .and_then(|value| value.to_str().ok())
        .and_then(trim_non_empty)
    {
        return Some(token.to_owned());
    }

    None
}

fn parse_authorization(raw: &str) -> Option<String> {
    let header = raw.trim();
    if header.is_empty() {
        return None;
    }

    let split_idx = header
        .char_indices()
        .find_map(|(idx, ch)| ch.is_ascii_whitespace().then_some(idx))?;
    let scheme = header[..split_idx].trim();
    let value = header[split_idx..].trim();

    if scheme.is_empty() || value.is_empty() {
        return None;
    }

    if scheme.eq_ignore_ascii_case("Bearer") {
        return Some(value.to_string());
    }

    if scheme.eq_ignore_ascii_case("Basic") {
        return parse_basic_authorization(value);
    }

    None
}

fn parse_basic_authorization(value: &str) -> Option<String> {
    let decoded = BASE64_STANDARD.decode(value).ok()?;
    if decoded.is_empty() {
        return None;
    }

    let decoded = String::from_utf8(decoded).ok()?;
    let decoded = decoded.trim();
    if decoded.is_empty() {
        return None;
    }

    if let Some((user, pass)) = decoded.split_once(':') {
        let pass = pass.trim();
        if !pass.is_empty() {
            return Some(pass.to_string());
        }

        let user = user.trim();
        if !user.is_empty() {
            return Some(user.to_string());
        }

        return None;
    }

    Some(decoded.to_string())
}

fn trim_non_empty(token: &str) -> Option<&str> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn hash_token(token: &str, key: &[u8; 32]) -> String {
    blake3::keyed_hash(key, token.as_bytes())
        .to_hex()
        .to_string()
}

fn generate_token(length: usize) -> String {
    const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = OsRng;
    let mut bytes = vec![0u8; length];
    rng.try_fill_bytes(&mut bytes)
        .expect("operating system RNG unavailable");
    bytes
        .into_iter()
        .map(|b| ALPHANUMERIC[(b as usize) % ALPHANUMERIC.len()] as char)
        .collect()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{HeaderValue, header};
    use fred::interfaces::KeysInterface;
    use fred::prelude::{Builder, Config};
    use serial_test::serial;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    const TEST_BLAKE3_KEY: [u8; 32] = [0u8; 32];

    async fn setup_test_client() -> fred::clients::Client {
        let config = Config::from_url("redis://localhost:6379").expect("invalid redis url");
        let client = Builder::from_config(config)
            .build()
            .expect("failed to build redis client");
        client.connect();
        client
            .wait_for_connect()
            .await
            .expect("failed to connect to redis");
        client
    }

    fn test_suffix() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let thread_id = std::thread::current().id();

        format!("{}_{}_{:?}", nanos, counter, thread_id)
    }

    async fn cleanup_token(client: &fred::clients::Client, token_hash: &str, user_sub: &str) {
        let _ = storage::delete_api_token(client, token_hash).await;
        let _: Result<(), _> = client.del(format!("auth:user_tokens:{}", user_sub)).await;
    }

    #[tokio::test]
    #[serial]
    async fn build_router_registers_routes_without_panic() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };

        // If the route definitions use an invalid syntax (e.g. old `:param` segments),
        // axum panics when constructing the router. This ensures we notice regressions.
        let _ = build_router(state);
    }

    #[tokio::test]
    async fn api_error_into_response_sets_status_and_body() {
        let error = ApiError::bad_request("invalid input");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = to_bytes(response.into_body(), 128)
            .await
            .expect("body bytes");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert_eq!(body, r#"{"message":"invalid input"}"#);
    }

    #[test]
    fn hash_token_is_deterministic() {
        let first = hash_token("example-token", &TEST_BLAKE3_KEY);
        let second = hash_token("example-token", &TEST_BLAKE3_KEY);
        assert_eq!(first, second);
        // Hash with keyed blake3 using all-zeros key
        assert_eq!(
            first,
            "2d00e35e3e78f77fa4eb0454a48fb41e45963e0f9b5a335be231a2b582790189"
        );
    }

    #[test]
    fn generate_token_uses_alphanumeric_charset() {
        let token = generate_token(64);
        assert_eq!(token.len(), 64);
        assert!(
            token.chars().all(|c| c.is_ascii_alphanumeric()),
            "token contains unexpected characters"
        );
    }

    #[test]
    fn extract_token_prefers_query_parameter() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        headers.append("X-API-Token", HeaderValue::from_static("header-fallback"));

        let token = extract_token(Some(" query-token "), &headers);
        assert_eq!(token.as_deref(), Some("query-token"));
    }

    #[test]
    fn extract_token_reads_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token "),
        );
        let token = extract_token(None, &headers);
        assert_eq!(token.as_deref(), Some("header-token"));

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Token", HeaderValue::from_static(" api-token "));
        let token = extract_token(None, &headers);
        assert_eq!(token.as_deref(), Some("api-token"));
    }

    #[test]
    fn extract_token_returns_none_when_unavailable() {
        let headers = HeaderMap::new();
        assert!(extract_token(None, &headers).is_none());
    }

    #[test]
    fn extract_token_supports_case_insensitive_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer MixedCaseToken"),
        );

        let token = extract_token(None, &headers);
        assert_eq!(token.as_deref(), Some("MixedCaseToken"));
    }

    #[test]
    fn extract_token_supports_basic_auth() {
        let mut headers = HeaderMap::new();
        let encoded = BASE64_STANDARD.encode("token-user:my-secret-token");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );

        let token = extract_token(None, &headers);
        assert_eq!(token.as_deref(), Some("my-secret-token"));

        let encoded = BASE64_STANDARD.encode("token-without-password:");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );

        let token = extract_token(None, &headers);
        assert_eq!(token.as_deref(), Some("token-without-password"));
    }

    #[tokio::test]
    #[serial]
    async fn live_endpoint_returns_ok() {
        let response = live().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[serial]
    async fn ready_returns_ready_when_ping_succeeds() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };

        let Json(status) = ready(State(state)).await.expect("ready ok");
        assert_eq!(status.status, "ready");
    }

    #[tokio::test]
    #[serial]
    async fn list_tokens_returns_stored_tokens() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };
        let sub = format!("user_{}", test_suffix());

        let token_one = "token-one";
        let token_two = "token-two";
        let hash_one = hash_token(token_one, &TEST_BLAKE3_KEY);
        let hash_two = hash_token(token_two, &TEST_BLAKE3_KEY);

        storage::create_api_token(&client, &sub, &hash_one, "first")
            .await
            .expect("store first token");
        storage::create_api_token(&client, &sub, &hash_two, "")
            .await
            .expect("store second token");

        let Json(tokens) = list_tokens(State(state), Path(sub.clone()))
            .await
            .expect("list tokens");

        assert_eq!(tokens.len(), 2);
        assert!(
            tokens
                .iter()
                .any(|t| t.id == hash_one && t.description == Some("first".into()))
        );
        assert!(
            tokens
                .iter()
                .any(|t| t.id == hash_two && t.description.is_none())
        );

        cleanup_token(&client, &hash_one, &sub).await;
        cleanup_token(&client, &hash_two, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn create_token_stores_and_returns_token() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };
        let sub = format!("user_{}", test_suffix());

        let payload = CreateTokenRequest {
            description: Some("api access".into()),
        };

        let (status, Json(response)) =
            create_token(State(state.clone()), Path(sub.clone()), Json(payload))
                .await
                .expect("token created");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(response.sub, sub);
        assert_eq!(response.description.as_deref(), Some("api access"));
        assert_eq!(response.token.len(), 32); // 256 bits
        assert_eq!(hash_token(&response.token, &TEST_BLAKE3_KEY), response.id);

        let stored = storage::read_api_token(&client, &response.id)
            .await
            .expect("read token")
            .expect("token present");
        assert_eq!(stored.sub, sub);

        cleanup_token(&client, &response.id, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn create_token_rejects_empty_subject() {
        let client = setup_test_client().await;
        let state = AppState {
            client,
            blake3_key: TEST_BLAKE3_KEY,
        };

        let payload = CreateTokenRequest { description: None };

        let err = create_token(State(state), Path(String::new()), Json(payload))
            .await
            .expect_err("subject validation should fail");

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial]
    async fn create_token_rejects_overlong_description() {
        let client = setup_test_client().await;
        let state = AppState {
            client,
            blake3_key: TEST_BLAKE3_KEY,
        };
        let sub = format!("user_{}", test_suffix());
        let payload = CreateTokenRequest {
            description: Some("x".repeat(MAX_DESCRIPTION_LENGTH + 1)),
        };

        let err = create_token(State(state), Path(sub), Json(payload))
            .await
            .expect_err("description validation should fail");

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial]
    async fn delete_token_removes_existing_token() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };
        let sub = format!("user_{}", test_suffix());
        let token = "delete-me";
        let hash = hash_token(token, &TEST_BLAKE3_KEY);

        storage::create_api_token(&client, &sub, &hash, "")
            .await
            .expect("store token");

        let status = delete_token(State(state), Path((sub.clone(), hash.clone())))
            .await
            .expect("delete ok");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let stored = storage::read_api_token(&client, &hash)
            .await
            .expect("read token");
        assert!(stored.is_none());

        cleanup_token(&client, &hash, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn delete_token_fails_for_wrong_owner() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };
        let real_sub = format!("user_{}", test_suffix());
        let wrong_sub = format!("user_{}", test_suffix());
        let token = "wrong-owner";
        let hash = hash_token(token, &TEST_BLAKE3_KEY);

        storage::create_api_token(&client, &real_sub, &hash, "")
            .await
            .expect("store token");

        let err = delete_token(State(state), Path((wrong_sub.clone(), hash.clone())))
            .await
            .expect_err("should fail");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        cleanup_token(&client, &hash, &real_sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn forward_auth_accepts_query_token() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };
        let sub = format!("user_{}", test_suffix());
        let token = "forward-query";
        let hash = hash_token(token, &TEST_BLAKE3_KEY);

        // Clean up any leftover data from previous failed test runs
        let _ = storage::delete_api_token(&client, &hash).await;

        storage::create_api_token(&client, &sub, &hash, "")
            .await
            .expect("store token");

        let headers = HeaderMap::new();
        let response = forward_auth(
            State(state),
            Query(ForwardAuthQuery {
                token: Some(token.to_string()),
            }),
            headers,
        )
        .await
        .expect("auth ok");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("X-Authenticated-User")
                .map(|v| v.to_str().unwrap()),
            Some(sub.as_str())
        );
        assert_eq!(
            response
                .headers()
                .get("X-Authenticated-Token-Id")
                .map(|v| v.to_str().unwrap()),
            Some(hash.as_str())
        );

        cleanup_token(&client, &hash, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn forward_auth_accepts_bearer_token() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };
        let sub = format!("user_{}", test_suffix());
        let token = "forward-header";
        let hash = hash_token(token, &TEST_BLAKE3_KEY);

        // Clean up any leftover data from previous failed test runs
        let _ = storage::delete_api_token(&client, &hash).await;

        storage::create_api_token(&client, &sub, &hash, "")
            .await
            .expect("store token");

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("bearer {}", token)).unwrap(),
        );
        let response = forward_auth(
            State(state),
            Query(ForwardAuthQuery { token: None }),
            headers,
        )
        .await
        .expect("auth ok");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        cleanup_token(&client, &hash, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn forward_auth_accepts_basic_token() {
        let client = setup_test_client().await;
        let state = AppState {
            client: client.clone(),
            blake3_key: TEST_BLAKE3_KEY,
        };
        let sub = format!("user_{}", test_suffix());
        let token = "forward-basic";
        let hash = hash_token(token, &TEST_BLAKE3_KEY);

        let _ = storage::delete_api_token(&client, &hash).await;

        storage::create_api_token(&client, &sub, &hash, "")
            .await
            .expect("store token");

        let mut headers = HeaderMap::new();
        let encoded = BASE64_STANDARD.encode(format!("ignored:{}", token));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );

        let response = forward_auth(
            State(state),
            Query(ForwardAuthQuery { token: None }),
            headers,
        )
        .await
        .expect("auth ok");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        cleanup_token(&client, &hash, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn forward_auth_rejects_missing_token() {
        let client = setup_test_client().await;
        let state = AppState {
            client,
            blake3_key: TEST_BLAKE3_KEY,
        };
        let headers = HeaderMap::new();

        let err = forward_auth(
            State(state),
            Query(ForwardAuthQuery { token: None }),
            headers,
        )
        .await
        .expect_err("should reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
}
