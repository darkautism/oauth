use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration as StdDuration,
};

use axum::{
    Json, Router,
    extract::{Extension, Form, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Duration, Utc};
use reqwest::{
    header::{ACCEPT, LOCATION},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use tokio::net::lookup_host;
use url::Url;
use uuid::Uuid;

use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct TokenPrefixes {
    pub client_id: String,
    pub client_secret: String,
    pub authorization_code: String,
    pub access_token: String,
    pub refresh_token: String,
}

impl TokenPrefixes {
    pub fn new(prefix: &str) -> Self {
        Self {
            client_id: format!("{prefix}c"),
            client_secret: format!("{prefix}s"),
            authorization_code: format!("{prefix}c"),
            access_token: format!("{prefix}a"),
            refresh_token: format!("{prefix}r"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum RedirectPolicy {
    /// Accept any HTTPS redirect URI plus HTTP loopback redirects.
    PublicMcp,
    /// Require explicitly allowed HTTPS hosts in production. Loopback HTTP
    /// redirect URIs remain allowed for native/desktop OAuth clients in all modes.
    Restricted {
        production: bool,
        allowed_hosts: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub service_name: String,
    pub scope: String,
    pub public_url: Option<String>,
    pub oauth_password: Option<String>,
    pub default_host: String,
    pub token_prefixes: TokenPrefixes,
    pub redirect_policy: RedirectPolicy,
    pub client_id_metadata_document_supported: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedClient {
    pub redirect_uris: Vec<String>,
    pub auth_method: String,
    pub secret_hash: Option<String>,
}

#[async_trait]
pub trait ExternalClientResolver: Send + Sync {
    async fn resolve(&self, client_id: &str) -> Result<Option<ResolvedClient>, String>;
}

pub struct OAuthState {
    db: sqlx::SqlitePool,
    pub config: OAuthConfig,
    redirect_policy: std::sync::RwLock<RedirectPolicy>,
    pub external_client_resolver: Option<Arc<dyn ExternalClientResolver>>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("create OAuth database directory: {0}")]
    Io(#[from] std::io::Error),
    #[error("open OAuth database: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migrate OAuth database: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

impl OAuthState {
    /// Open the crate-owned SQLite database at the requested path.
    /// Missing parent directories and the database file are created automatically.
    /// Schema migrations are embedded in this crate and run on every open.
    pub async fn open(path: impl AsRef<Path>, config: OAuthConfig) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal);
        let db = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&db).await?;

        let redirect_policy = config.redirect_policy.clone();
        Ok(Self {
            db,
            config,
            redirect_policy: std::sync::RwLock::new(redirect_policy),
            external_client_resolver: None,
        })
    }

    pub fn with_external_client_resolver(
        mut self,
        resolver: Arc<dyn ExternalClientResolver>,
    ) -> Self {
        self.external_client_resolver = Some(resolver);
        self
    }

    pub fn set_redirect_policy(&self, policy: RedirectPolicy) {
        let mut guard = self
            .redirect_policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = policy;
    }

    fn redirect_policy(&self) -> RedirectPolicy {
        self.redirect_policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

const ACCESS_TTL_SECS: i64 = 3600;
const CODE_TTL_SECS: i64 = 600;
const REFRESH_TTL_SECS: i64 = 30 * 24 * 3600;

pub fn router<S>(state: Arc<OAuthState>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::<S>::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata_root),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata_mcp),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/mcp",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration/mcp",
            get(authorization_server_metadata),
        )
        .route(
            "/mcp/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/mcp/.well-known/openid-configuration",
            get(authorization_server_metadata),
        )
        .route("/mcp/oauth/register", post(register_client))
        .route(
            "/mcp/oauth/authorize",
            get(authorize_get).post(authorize_post),
        )
        .route("/mcp/oauth/token", post(token))
        .layer(Extension(state))
}

fn issuer(state: &OAuthState, headers: &HeaderMap) -> String {
    if let Some(url) = &state.config.public_url {
        return url.clone();
    }

    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(state.config.default_host.as_str());

    let forwarded_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"))
        || headers
            .get(header::FORWARDED)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .chain(v.split(','))
                    .any(|part| part.trim().eq_ignore_ascii_case("proto=https"))
            })
        || headers
            .get("x-forwarded-port")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == "443");

    let authority_host = host
        .parse::<axum::http::uri::Authority>()
        .ok()
        .map(|a| a.host().to_ascii_lowercase())
        .unwrap_or_else(|| host.to_ascii_lowercase());
    let local = matches!(authority_host.as_str(), "localhost" | "127.0.0.1" | "::1");

    let scheme = if forwarded_https || !local {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{host}")
}

fn resource_url(state: &OAuthState, headers: &HeaderMap) -> String {
    format!("{}/mcp", issuer(state, headers))
}

async fn protected_resource_metadata_root(
    Extension(state): Extension<Arc<OAuthState>>,
    headers: HeaderMap,
) -> Json<Value> {
    let origin = issuer(&state, &headers);
    // MCPX keeps one canonical protected resource even when a compatibility
    // root endpoint is reachable: the MCP resource is always {origin}/mcp.
    protected_resource_metadata_response(format!("{origin}/mcp"), origin, &state.config.scope)
}

async fn protected_resource_metadata_mcp(
    Extension(state): Extension<Arc<OAuthState>>,
    headers: HeaderMap,
) -> Json<Value> {
    let origin = issuer(&state, &headers);
    protected_resource_metadata_response(format!("{origin}/mcp"), origin, &state.config.scope)
}

fn protected_resource_metadata_response(
    resource: String,
    authorization_server: String,
    scope: &str,
) -> Json<Value> {
    Json(json!({
        "resource": resource,
        "authorization_servers": [authorization_server],
        "scopes_supported": [scope],
        "bearer_methods_supported": ["header"]
    }))
}

async fn authorization_server_metadata(
    Extension(state): Extension<Arc<OAuthState>>,
    headers: HeaderMap,
) -> Json<Value> {
    let origin = issuer(&state, &headers);
    let mut metadata = json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/mcp/oauth/authorize"),
        "token_endpoint": format!("{origin}/mcp/oauth/token"),
        "registration_endpoint": format!("{origin}/mcp/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "scopes_supported": [state.config.scope.as_str()],
        "registration_endpoint_auth_methods_supported": ["none"]
    });
    if state.config.client_id_metadata_document_supported {
        metadata["client_id_metadata_document_supported"] = Value::Bool(true);
    }
    Json(metadata)
}

#[derive(Debug, Deserialize)]
struct ClientRegistration {
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default = "default_auth_method")]
    token_endpoint_auth_method: String,
}

fn default_auth_method() -> String {
    "none".into()
}

async fn register_client(
    Extension(state): Extension<Arc<OAuthState>>,
    Json(input): Json<ClientRegistration>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    if input.redirect_uris.is_empty()
        || input
            .redirect_uris
            .iter()
            .any(|uri| !valid_redirect_uri(&state, uri))
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "invalid redirect_uris",
        ));
    }

    if !matches!(
        input.token_endpoint_auth_method.as_str(),
        "none" | "client_secret_post" | "client_secret_basic"
    ) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "unsupported token_endpoint_auth_method",
        ));
    }

    let client_id = format!(
        "{}_{}",
        state.config.token_prefixes.client_id,
        Uuid::new_v4().simple()
    );
    let client_secret = (input.token_endpoint_auth_method != "none")
        .then(|| random_token(&state.config.token_prefixes.client_secret));

    sqlx::query(
        "INSERT INTO oauth_clients(client_id,client_secret_hash,redirect_uris,token_endpoint_auth_method,client_name,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(&client_id)
    .bind(client_secret.as_deref().map(hash))
    .bind(serde_json::to_string(&input.redirect_uris).map_err(internal_oauth)?)
    .bind(&input.token_endpoint_auth_method)
    .bind(&input.client_name)
    .bind(Utc::now().to_rfc3339())
    .execute(&state.db)
    .await
    .map_err(internal_oauth)?;

    let mut out = json!({
        "client_id": client_id,
        "redirect_uris": input.redirect_uris,
        "client_name": input.client_name,
        "token_endpoint_auth_method": input.token_endpoint_auth_method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"]
    });

    if let Some(secret) = client_secret {
        out["client_secret"] = Value::String(secret);
        out["client_secret_expires_at"] = Value::from(0);
    }

    Ok((StatusCode::CREATED, Json(out)))
}

fn is_loopback_redirect_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn valid_redirect_uri(state: &OAuthState, raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };

    let redirect_policy = state.redirect_policy();
    match &redirect_policy {
        RedirectPolicy::PublicMcp => match url.scheme() {
            "https" => true,
            "http" => is_loopback_redirect_host(host),
            _ => false,
        },
        RedirectPolicy::Restricted {
            production,
            allowed_hosts,
        } => match url.scheme() {
            "https" => host_allowed(*production, allowed_hosts, host),
            // RFC 8252 loopback redirects are the standard OAuth callback for
            // native/desktop clients. They are safe to allow in production
            // because the host must resolve to the loopback interface; the
            // random port is selected by the local client.
            "http" => is_loopback_redirect_host(host),
            _ => false,
        },
    }
}

fn host_allowed(production: bool, allowed_hosts: &[String], host: &str) -> bool {
    if allowed_hosts.is_empty() {
        return !production;
    }

    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allowed_hosts.iter().any(|pattern| {
        let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host != suffix && host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern
        }
    })
}

const MAX_CIMD_BODY: usize = 1 << 20;
const MAX_CIMD_REDIRECTS: usize = 8;

#[derive(Debug, Deserialize)]
struct ClientMetadataDocument {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

fn is_cimd_client_id(client_id: &str) -> bool {
    if client_id.is_empty() || client_id.len() > 2048 {
        return false;
    }
    let Ok(url) = Url::parse(client_id) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.path() != "/"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

async fn resolve_cimd_client(
    state: &OAuthState,
    client_id: &str,
) -> Result<ResolvedClient, String> {
    if !is_cimd_client_id(client_id) {
        return Err("client_id is not an HTTPS metadata document URL".into());
    }

    let mut current = Url::parse(client_id).map_err(|e| format!("parse CIMD URL: {e}"))?;
    let mut response = None;
    for redirects in 0..=MAX_CIMD_REDIRECTS {
        validate_public_cimd_url(&current)?;
        let endpoint = resolve_public_endpoint(&current).await?;
        let host = current
            .host_str()
            .ok_or_else(|| "CIMD URL has no host".to_string())?;

        let mut builder = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(10))
            .redirect(Policy::none());
        if host.parse::<IpAddr>().is_err() {
            builder = builder.resolve(host, endpoint);
        }
        let client = builder
            .build()
            .map_err(|e| format!("build CIMD client: {e}"))?;
        let resp = client
            .get(current.clone())
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("fetch CIMD: {e}"))?;

        if resp.status().is_redirection() {
            if redirects >= MAX_CIMD_REDIRECTS {
                return Err("too many CIMD redirects".into());
            }
            let location = resp
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "CIMD redirect lacks Location".to_string())?;
            current = current
                .join(location)
                .map_err(|e| format!("invalid CIMD redirect: {e}"))?;
            continue;
        }
        response = Some(resp);
        break;
    }

    let mut response = response.ok_or_else(|| "CIMD redirect limit exceeded".to_string())?;
    if !response.status().is_success() {
        return Err(format!("fetch CIMD: HTTP {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_CIMD_BODY as u64)
    {
        return Err("CIMD document exceeds size limit".into());
    }
    let mut raw = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("read CIMD: {e}"))?
    {
        if raw.len() + chunk.len() > MAX_CIMD_BODY {
            return Err("CIMD document exceeds size limit".into());
        }
        raw.extend_from_slice(&chunk);
    }

    let doc: ClientMetadataDocument =
        serde_json::from_slice(&raw).map_err(|e| format!("parse CIMD: {e}"))?;
    if !doc.client_id.is_empty() && doc.client_id != client_id {
        return Err("CIMD client_id mismatch".into());
    }
    if doc.redirect_uris.is_empty()
        || doc
            .redirect_uris
            .iter()
            .any(|uri| !valid_redirect_uri(state, uri))
    {
        return Err("CIMD contains redirect_uris rejected by policy".into());
    }

    let mut method = doc.token_endpoint_auth_method.trim().to_string();
    if method.is_empty()
        && doc
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|candidate| candidate == "none")
    {
        method = "none".into();
    }
    if method.is_empty() {
        method = "none".into();
    }
    if method != "none" {
        if doc
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|candidate| candidate == "none")
        {
            method = "none".into();
        } else {
            return Err(format!(
                "unsupported CIMD token_endpoint_auth_method {method:?}"
            ));
        }
    }

    Ok(ResolvedClient {
        redirect_uris: doc.redirect_uris,
        auth_method: method,
        secret_hash: None,
    })
}

fn validate_public_cimd_url(url: &Url) -> Result<(), String> {
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err("CIMD URL is not allowed".into());
    }
    Ok(())
}

async fn resolve_public_endpoint(url: &Url) -> Result<SocketAddr, String> {
    validate_public_cimd_url(url)?;
    let host = url
        .host_str()
        .ok_or_else(|| "CIMD URL has no host".to_string())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "CIMD URL has no usable port".to_string())?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err("CIMD address is not public".into());
        }
        return Ok(SocketAddr::new(ip, port));
    }

    let addrs = lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve CIMD host: {e}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err("CIMD host resolved to no addresses".into());
    }
    if addrs.iter().any(|addr| !is_public_ip(addr.ip())) {
        return Err("CIMD host resolved to a private or special-use address".into());
    }
    Ok(addrs[0])
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            is_public_v6(ip)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    (segments[0] & 0xe000) == 0x2000
}

fn client_redirect_allowed(client_id: &str, client: &ResolvedClient, redirect_uri: &str) -> bool {
    if client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
        return true;
    }
    if !is_cimd_client_id(client_id) {
        return false;
    }

    let Ok(url) = Url::parse(redirect_uri) else {
        return false;
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }

    let Some(host) = url.host_str().map(|host| host.to_ascii_lowercase()) else {
        return false;
    };
    if !matches!(
        host.as_str(),
        "chatgpt.com" | "www.chatgpt.com" | "chat.openai.com"
    ) {
        return false;
    }

    let path = url.path();
    path == "/connector_platform_oauth_redirect"
        || (path.starts_with("/connector/oauth/") && path.len() > "/connector/oauth/".len())
}

async fn resolve_client(state: &OAuthState, client_id: &str) -> Result<ResolvedClient, String> {
    let row = sqlx::query(
        "SELECT redirect_uris,token_endpoint_auth_method,client_secret_hash FROM oauth_clients WHERE client_id=?",
    )
    .bind(client_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("read OAuth client: {e}"))?;

    if let Some(row) = row {
        let raw: String = row
            .try_get("redirect_uris")
            .map_err(|e| format!("read redirect_uris: {e}"))?;
        let redirect_uris =
            serde_json::from_str(&raw).map_err(|e| format!("parse redirect_uris: {e}"))?;

        return Ok(ResolvedClient {
            redirect_uris,
            auth_method: row
                .try_get("token_endpoint_auth_method")
                .map_err(|e| format!("read auth method: {e}"))?,
            secret_hash: row
                .try_get("client_secret_hash")
                .map_err(|e| format!("read client secret: {e}"))?,
        });
    }

    if let Some(resolver) = &state.external_client_resolver {
        if let Some(client) = resolver.resolve(client_id).await? {
            return Ok(client);
        }
    }

    if state.config.client_id_metadata_document_supported && is_cimd_client_id(client_id) {
        return resolve_cimd_client(state, client_id).await;
    }

    Err("unknown client".into())
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn authorize_get(
    Extension(state): Extension<Arc<OAuthState>>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Html<String>, (StatusCode, String)> {
    validate_authorize(&state, &params).await?;
    let method = params
        .code_challenge_method
        .clone()
        .unwrap_or_else(|| "S256".into());

    let service = esc(&state.config.service_name);
    let form = format!(
        r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize {}</title>
<style>
  :root {{
    --bg: #f4f5f7;
    --card: #ffffff;
    --text: #1a1d23;
    --muted: #6b7280;
    --border: #e2e4e9;
    --accent: #2f6feb;
    --accent-hover: #2557c4;
    --danger: #d1373f;
    color-scheme: light dark;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0f1115;
      --card: #181b21;
      --text: #e7e9ee;
      --muted: #9198a6;
      --border: #2a2e37;
      --accent: #5b8cff;
      --accent-hover: #7ca0ff;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1.5rem;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  .card {{
    width: 100%;
    max-width: 24rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 2rem 1.75rem;
    box-shadow: 0 1px 2px rgba(16, 24, 40, .04), 0 8px 24px rgba(16, 24, 40, .08);
  }}
  .badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 2.75rem;
    height: 2.75rem;
    border-radius: 12px;
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent);
    margin-bottom: 1rem;
  }}
  h1 {{
    font-size: 1.25rem;
    font-weight: 650;
    margin: 0 0 .35rem;
    letter-spacing: -.01em;
  }}
  .subtitle {{
    margin: 0 0 1.5rem;
    color: var(--muted);
    font-size: .9rem;
    line-height: 1.45;
  }}
  .subtitle code {{
    background: color-mix(in srgb, var(--muted) 14%, transparent);
    padding: .1rem .4rem;
    border-radius: 6px;
    font-size: .82rem;
    word-break: break-all;
  }}
  label {{
    display: block;
    font-size: .82rem;
    font-weight: 600;
    margin-bottom: .4rem;
    color: var(--text);
  }}
  input[type=password] {{
    width: 100%;
    padding: .7rem .8rem;
    font-size: 1rem;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--bg);
    color: var(--text);
    outline: none;
    transition: border-color .15s, box-shadow .15s;
  }}
  input[type=password]:focus {{
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent);
  }}
  button {{
    width: 100%;
    margin-top: 1.1rem;
    padding: .75rem 1rem;
    font-size: .95rem;
    font-weight: 600;
    color: #fff;
    background: var(--accent);
    border: none;
    border-radius: 10px;
    cursor: pointer;
    transition: background .15s;
  }}
  button:hover {{ background: var(--accent-hover); }}
  button:active {{ transform: translateY(1px); }}
  .footer {{
    margin-top: 1.25rem;
    text-align: center;
    font-size: .78rem;
    color: var(--muted);
  }}
</style>
<div class="card">
  <div class="badge">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2"></rect>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
    </svg>
  </div>
  <h1>Authorize {}</h1>
  <p class="subtitle">An application is requesting access. Client: <code>{}</code></p>
  <form method="post" action="/mcp/oauth/authorize">
    <input type="hidden" name="client_id" value="{}">
    <input type="hidden" name="redirect_uri" value="{}">
    <input type="hidden" name="code_challenge" value="{}">
    <input type="hidden" name="code_challenge_method" value="{}">
    <input type="hidden" name="state" value="{}">
    <input type="hidden" name="resource" value="{}">
    <input type="hidden" name="scope" value="{}">
    <label for="pw">{} password</label>
    <input id="pw" type="password" name="password" autocomplete="current-password" autofocus required>
    <button type="submit">Authorize</button>
  </form>
  <p class="footer">Only continue if you trust this application.</p>
</div>"#,
        service,
        service,
        esc(&params.client_id),
        esc(&params.client_id),
        esc(&params.redirect_uri),
        esc(&params.code_challenge),
        esc(&method),
        esc(params.state.as_deref().unwrap_or("")),
        esc(params.resource.as_deref().unwrap_or("")),
        esc(params
            .scope
            .as_deref()
            .unwrap_or(state.config.scope.as_str())),
        service,
    );

    Ok(Html(form))
}

#[derive(Debug, Deserialize)]
struct AuthorizeForm {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    resource: String,
    #[serde(default)]
    scope: String,
    password: String,
}

async fn authorize_post(
    Extension(state): Extension<Arc<OAuthState>>,
    headers: HeaderMap,
    Form(form): Form<AuthorizeForm>,
) -> Result<Redirect, (StatusCode, String)> {
    let params = AuthorizeParams {
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: Some(form.code_challenge_method.clone()),
        state: Some(form.state.clone()),
        resource: (!form.resource.is_empty()).then(|| form.resource.clone()),
        scope: (!form.scope.is_empty()).then(|| form.scope.clone()),
    };

    validate_authorize(&state, &params).await?;

    let expected = state.config.oauth_password.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "OAuth password is not configured".into(),
    ))?;
    if hash(expected) != hash(&form.password) {
        return Err((StatusCode::UNAUTHORIZED, "invalid password".into()));
    }

    let code = random_token(&state.config.token_prefixes.authorization_code);
    let resource = params
        .resource
        .unwrap_or_else(|| resource_url(&state, &headers));
    let scope = params
        .scope
        .unwrap_or_else(|| state.config.scope.as_str().into());

    sqlx::query(
        "INSERT INTO oauth_codes(code_hash,client_id,redirect_uri,code_challenge,resource,scope,expires_at,used) VALUES(?,?,?,?,?,?,?,0)",
    )
    .bind(hash(&code))
    .bind(&form.client_id)
    .bind(&form.redirect_uri)
    .bind(&form.code_challenge)
    .bind(resource)
    .bind(scope)
    .bind((Utc::now() + Duration::seconds(CODE_TTL_SECS)).to_rfc3339())
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut redirect = Url::parse(&form.redirect_uri)
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad redirect_uri".into()))?;
    redirect.query_pairs_mut().append_pair("code", &code);
    if !form.state.is_empty() {
        redirect.query_pairs_mut().append_pair("state", &form.state);
    }
    Ok(Redirect::to(redirect.as_str()))
}

async fn validate_authorize(
    state: &OAuthState,
    params: &AuthorizeParams,
) -> Result<(), (StatusCode, String)> {
    if params.client_id.is_empty()
        || params.redirect_uri.is_empty()
        || params.code_challenge.is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing client_id, redirect_uri, or code_challenge".into(),
        ));
    }

    if params.code_challenge_method.as_deref().unwrap_or("S256") != "S256"
        || params.code_challenge.len() < 43
    {
        return Err((StatusCode::BAD_REQUEST, "PKCE S256 is required".into()));
    }

    if !valid_redirect_uri(state, &params.redirect_uri) {
        return Err((
            StatusCode::FORBIDDEN,
            "OAuth redirect host is not allowed".into(),
        ));
    }

    let client = resolve_client(state, &params.client_id)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    if !client_redirect_allowed(&params.client_id, &client, &params.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            "redirect_uri is not registered".into(),
        ));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    resource: String,
}

async fn token(
    Extension(state): Extension<Arc<OAuthState>>,
    headers: HeaderMap,
    Form(mut form): Form<TokenForm>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Some((id, secret)) = parse_basic(&headers) {
        form.client_id = id;
        form.client_secret = secret;
    }

    if form.client_id.is_empty() {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "missing client_id",
        ));
    }

    authenticate_client(&state, &form.client_id, &form.client_secret).await?;

    match form.grant_type.as_str() {
        "authorization_code" => exchange_code(&state, form).await,
        "refresh_token" => exchange_refresh(&state, form).await,
        _ => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "unsupported grant_type",
        )),
    }
}

async fn authenticate_client(
    state: &OAuthState,
    client_id: &str,
    supplied_secret: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let client = resolve_client(state, client_id)
        .await
        .map_err(|e| oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", &e))?;

    if client.auth_method == "none" {
        return Ok(());
    }

    let supplied_hash = hash(supplied_secret);
    if supplied_secret.is_empty() || client.secret_hash.as_deref() != Some(supplied_hash.as_str()) {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        ));
    }

    Ok(())
}

async fn exchange_code(
    state: &OAuthState,
    form: TokenForm,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut tx = state.db.begin().await.map_err(internal_oauth)?;

    let row = sqlx::query(
        "SELECT client_id,redirect_uri,code_challenge,resource,scope,expires_at,used FROM oauth_codes WHERE code_hash=?",
    )
    .bind(hash(&form.code))
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal_oauth)?
    .ok_or_else(|| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "unknown authorization code",
        )
    })?;

    let used: i64 = row.try_get("used").map_err(internal_oauth)?;
    let expires: String = row.try_get("expires_at").map_err(internal_oauth)?;
    if used != 0 || parse_time(&expires) <= Utc::now() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code expired or used",
        ));
    }

    let client_id: String = row.try_get("client_id").map_err(internal_oauth)?;
    let redirect_uri: String = row.try_get("redirect_uri").map_err(internal_oauth)?;
    let challenge: String = row.try_get("code_challenge").map_err(internal_oauth)?;

    if client_id != form.client_id
        || redirect_uri != form.redirect_uri
        || pkce_challenge(&form.code_verifier) != challenge
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code validation failed",
        ));
    }

    let stored_resource: String = row.try_get("resource").map_err(internal_oauth)?;
    if !form.resource.is_empty() && form.resource != stored_resource {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource mismatch",
        ));
    }

    let resource = if form.resource.is_empty() {
        stored_resource
    } else {
        form.resource.clone()
    };
    let scope: String = row.try_get("scope").map_err(internal_oauth)?;

    sqlx::query("UPDATE oauth_codes SET used=1 WHERE code_hash=?")
        .bind(hash(&form.code))
        .execute(&mut *tx)
        .await
        .map_err(internal_oauth)?;

    let (access, refresh) = issue_tokens(
        &mut tx,
        &form.client_id,
        &resource,
        &scope,
        &state.config.token_prefixes,
    )
    .await?;
    tx.commit().await.map_err(internal_oauth)?;

    Ok(Json(token_response(access, refresh, &scope)))
}

async fn exchange_refresh(
    state: &OAuthState,
    form: TokenForm,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut tx = state.db.begin().await.map_err(internal_oauth)?;

    let row = sqlx::query(
        "SELECT client_id,resource,scope,expires_at,revoked FROM oauth_refresh_tokens WHERE token_hash=?",
    )
    .bind(hash(&form.refresh_token))
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal_oauth)?
    .ok_or_else(|| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "unknown refresh token",
        )
    })?;

    let client_id: String = row.try_get("client_id").map_err(internal_oauth)?;
    let revoked: i64 = row.try_get("revoked").map_err(internal_oauth)?;
    let expires: String = row.try_get("expires_at").map_err(internal_oauth)?;

    if client_id != form.client_id || revoked != 0 || parse_time(&expires) <= Utc::now() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token expired, revoked, or belongs to another client",
        ));
    }

    let stored_resource: String = row.try_get("resource").map_err(internal_oauth)?;
    if !form.resource.is_empty() && form.resource != stored_resource {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource mismatch",
        ));
    }
    let scope: String = row.try_get("scope").map_err(internal_oauth)?;

    sqlx::query("UPDATE oauth_refresh_tokens SET revoked=1 WHERE token_hash=?")
        .bind(hash(&form.refresh_token))
        .execute(&mut *tx)
        .await
        .map_err(internal_oauth)?;

    let (access, refresh) = issue_tokens(
        &mut tx,
        &form.client_id,
        &stored_resource,
        &scope,
        &state.config.token_prefixes,
    )
    .await?;
    tx.commit().await.map_err(internal_oauth)?;

    Ok(Json(token_response(access, refresh, &scope)))
}

async fn issue_tokens(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    client_id: &str,
    resource: &str,
    scope: &str,
    prefixes: &TokenPrefixes,
) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let now = Utc::now();
    let access = random_token(&prefixes.access_token);
    let refresh = random_token(&prefixes.refresh_token);

    sqlx::query(
        "INSERT INTO oauth_access_tokens(token_hash,client_id,resource,scope,expires_at,revoked,created_at) VALUES(?,?,?,?,?,0,?)",
    )
    .bind(hash(&access))
    .bind(client_id)
    .bind(resource)
    .bind(scope)
    .bind((now + Duration::seconds(ACCESS_TTL_SECS)).to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&mut **tx)
    .await
    .map_err(internal_oauth)?;

    sqlx::query(
        "INSERT INTO oauth_refresh_tokens(token_hash,client_id,resource,scope,expires_at,revoked) VALUES(?,?,?,?,?,0)",
    )
    .bind(hash(&refresh))
    .bind(client_id)
    .bind(resource)
    .bind(scope)
    .bind((now + Duration::seconds(REFRESH_TTL_SECS)).to_rfc3339())
    .execute(&mut **tx)
    .await
    .map_err(internal_oauth)?;

    Ok((access, refresh))
}

fn token_response(access: String, refresh: String, scope: &str) -> Value {
    json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SECS,
        "refresh_token": refresh,
        "scope": scope
    })
}

pub async fn require_mcp_auth(
    State(state): State<Arc<OAuthState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let origin = issuer(&state, &headers);
    // Match MCPX: the protected resource identity is always /mcp. A root
    // route may remain as a compatibility alias, but it must not mint or
    // validate a second OAuth audience.
    let resource = format!("{origin}/mcp");

    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let valid = match token {
        Some(token) => validate_access_token(&state, token, &resource).await,
        None => false,
    };

    if !valid {
        let metadata = format!("{origin}/.well-known/oauth-protected-resource/mcp");

        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                format!(
                    "Bearer realm=\"{}\", resource_metadata=\"{metadata}\", scope=\"{}\"",
                    state.config.service_name.to_ascii_lowercase(),
                    state.config.scope
                ),
            )],
            "unauthorized",
        )
            .into_response();
    }

    next.run(request).await
}

async fn validate_access_token(state: &OAuthState, token: &str, resource: &str) -> bool {
    let row = sqlx::query(
        "SELECT resource,expires_at,revoked FROM oauth_access_tokens WHERE token_hash=?",
    )
    .bind(hash(token))
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let Some(row) = row else {
        return false;
    };

    let Ok(stored_resource): Result<String, _> = row.try_get("resource") else {
        return false;
    };
    let Ok(expires): Result<String, _> = row.try_get("expires_at") else {
        return false;
    };
    let Ok(revoked): Result<i64, _> = row.try_get("revoked") else {
        return false;
    };

    revoked == 0 && stored_resource == resource && parse_time(&expires) > Utc::now()
}

fn parse_basic(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;

    let decoded = String::from_utf8(STANDARD.decode(value).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn random_token(prefix: &str) -> String {
    format!(
        "{prefix}_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

fn hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn parse_time(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

fn esc(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn oauth_error(status: StatusCode, code: &str, description: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "error": code,
            "error_description": description
        })),
    )
}

fn internal_oauth(error: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        &error.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn config(public_url: Option<&str>, redirect_policy: RedirectPolicy) -> OAuthConfig {
        OAuthConfig {
            service_name: "Test".into(),
            scope: "test".into(),
            public_url: public_url.map(str::to_string),
            oauth_password: None,
            default_host: "127.0.0.1:9999".into(),
            token_prefixes: TokenPrefixes::new("t"),
            redirect_policy,
            client_id_metadata_document_supported: true,
        }
    }

    fn state(public_url: Option<&str>, redirect_policy: RedirectPolicy) -> OAuthState {
        let db = sqlx::SqlitePool::connect_lazy("sqlite::memory:").expect("lazy sqlite");
        let config = config(public_url, redirect_policy.clone());
        OAuthState {
            db,
            config,
            redirect_policy: std::sync::RwLock::new(redirect_policy),
            external_client_resolver: None,
        }
    }

    #[tokio::test]
    async fn explicit_public_url_is_authoritative() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("wrong.example"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        assert_eq!(
            issuer(
                &state(Some("https://correct.example"), RedirectPolicy::PublicMcp),
                &headers
            ),
            "https://correct.example"
        );
    }

    #[tokio::test]
    async fn public_host_defaults_to_https_without_explicit_public_url() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("random-subdomain.example.com"),
        );
        assert_eq!(
            issuer(&state(None, RedirectPolicy::PublicMcp), &headers),
            "https://random-subdomain.example.com"
        );
    }

    #[tokio::test]
    async fn localhost_without_proxy_headers_remains_http_for_development() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:9999"));
        assert_eq!(
            issuer(&state(None, RedirectPolicy::PublicMcp), &headers),
            "http://127.0.0.1:9999"
        );
    }

    #[tokio::test]
    async fn public_mcp_redirect_policy_accepts_https_and_loopback_only_for_http() {
        let state = state(None, RedirectPolicy::PublicMcp);
        assert!(valid_redirect_uri(&state, "https://example.com/callback"));
        assert!(valid_redirect_uri(&state, "http://127.0.0.1:1455/callback"));
        assert!(!valid_redirect_uri(&state, "http://example.com/callback"));
        assert!(!valid_redirect_uri(
            &state,
            "https://u:p@example.com/callback"
        ));
        assert!(!valid_redirect_uri(
            &state,
            "https://example.com/callback#fragment"
        ));
    }

    #[tokio::test]
    async fn restricted_redirect_policy_requires_allowlist_in_production() {
        let state = state(
            None,
            RedirectPolicy::Restricted {
                production: true,
                allowed_hosts: vec!["allowed.example".into(), "*.trusted.example".into()],
            },
        );
        assert!(valid_redirect_uri(&state, "https://allowed.example/cb"));
        assert!(valid_redirect_uri(&state, "https://a.trusted.example/cb"));
        assert!(!valid_redirect_uri(&state, "https://trusted.example/cb"));
        assert!(!valid_redirect_uri(&state, "https://evil.example/cb"));
        assert!(valid_redirect_uri(&state, "http://127.0.0.1:1455/cb"));
        assert!(valid_redirect_uri(&state, "http://localhost:1455/cb"));
        assert!(valid_redirect_uri(&state, "http://[::1]:1455/cb"));
        assert!(!valid_redirect_uri(&state, "http://127.0.0.1.evil.example:1455/cb"));
        assert!(!valid_redirect_uri(&state, "http://192.168.1.10:1455/cb"));
    }

    #[tokio::test]
    async fn redirect_policy_can_be_updated_without_reopening_state() {
        let state = state(
            None,
            RedirectPolicy::Restricted {
                production: true,
                allowed_hosts: vec!["chatgpt.com".into()],
            },
        );
        assert!(!valid_redirect_uri(
            &state,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        state.set_redirect_policy(RedirectPolicy::Restricted {
            production: true,
            allowed_hosts: vec!["chatgpt.com".into(), "claude.ai".into()],
        });
        assert!(valid_redirect_uri(
            &state,
            "https://claude.ai/api/mcp/auth_callback"
        ));
    }

    #[tokio::test]
    async fn root_metadata_uses_the_canonical_mcp_resource() {
        let state = Arc::new(state(Some("https://pc.example"), RedirectPolicy::PublicMcp));
        let Json(metadata) =
            protected_resource_metadata_root(Extension(state), HeaderMap::new()).await;
        assert_eq!(
            metadata.get("resource").and_then(Value::as_str),
            Some("https://pc.example/mcp")
        );
    }

    #[test]
    fn chatgpt_cimd_accepts_path_scoped_connector_callbacks() {
        let client = ResolvedClient {
            redirect_uris: vec!["https://chatgpt.com/connector_platform_oauth_redirect".into()],
            auth_method: "none".into(),
            secret_hash: None,
        };
        let client_id = "https://chatgpt.com/oauth/example/client.json";
        assert!(client_redirect_allowed(
            client_id,
            &client,
            "https://chatgpt.com/connector/oauth/callback-id"
        ));
        assert!(client_redirect_allowed(
            client_id,
            &client,
            "https://chat.openai.com/connector/oauth/callback-id"
        ));
        assert!(!client_redirect_allowed(
            client_id,
            &client,
            "https://example.com/connector/oauth/callback-id"
        ));
        assert!(!client_redirect_allowed(
            "opaque-client",
            &client,
            "https://chatgpt.com/connector/oauth/callback-id"
        ));
    }

    #[test]
    fn cimd_ids_require_https_metadata_documents() {
        assert!(is_cimd_client_id(
            "https://chatgpt.com/oauth/example/client.json"
        ));
        assert!(!is_cimd_client_id(
            "http://chatgpt.com/oauth/example/client.json"
        ));
        assert!(!is_cimd_client_id("https://chatgpt.com/"));
        assert!(!is_cimd_client_id("opaque-client-id"));
        assert!(!is_cimd_client_id(
            "https://user@chatgpt.com/oauth/example/client.json"
        ));
    }

    #[test]
    fn cimd_fetch_rejects_private_and_special_addresses() {
        for raw in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(
                !is_public_ip(raw.parse().unwrap()),
                "{raw} must be rejected"
            );
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn open_creates_parent_directory_database_and_schema() {
        let root = std::env::temp_dir().join(format!("oauth-storage-test-{}", Uuid::new_v4()));
        let path = root.join("nested").join("oauth.db");
        assert!(!path.exists());

        let opened = OAuthState::open(&path, config(None, RedirectPolicy::PublicMcp))
            .await
            .expect("open OAuth database");

        assert!(path.exists());
        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('oauth_clients','oauth_codes','oauth_refresh_tokens','oauth_access_tokens')",
        )
        .fetch_one(&opened.db)
        .await
        .unwrap();
        assert_eq!(tables, 4);

        drop(opened);
        let _ = std::fs::remove_dir_all(root);
    }
}
