use std::{path::Path, sync::Arc};

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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
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
    /// Require explicitly allowed HTTPS hosts in production. In development,
    /// an empty allow-list accepts HTTPS hosts and loopback HTTP.
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

        Ok(Self {
            db,
            config,
            external_client_resolver: None,
        })
    }

    /// Open a crate-owned database and import OAuth rows from a legacy application
    /// database exactly once. The source database is never modified.
    pub async fn open_migrating_legacy(
        path: impl AsRef<Path>,
        config: OAuthConfig,
        legacy_db: &sqlx::SqlitePool,
    ) -> Result<Self, StorageError> {
        let state = Self::open(path, config).await?;
        state.import_legacy_once(legacy_db).await?;
        Ok(state)
    }

    pub fn with_external_client_resolver(
        mut self,
        resolver: Arc<dyn ExternalClientResolver>,
    ) -> Self {
        self.external_client_resolver = Some(resolver);
        self
    }

    async fn import_legacy_once(&self, legacy_db: &sqlx::SqlitePool) -> Result<(), StorageError> {
        let imported: Option<String> =
            sqlx::query_scalar("SELECT value FROM oauth_meta WHERE key='legacy_import_complete'")
                .fetch_optional(&self.db)
                .await?;
        if imported.as_deref() == Some("1") {
            return Ok(());
        }

        let mut tx = self.db.begin().await?;
        copy_legacy_clients(legacy_db, &mut tx).await?;
        copy_legacy_codes(legacy_db, &mut tx).await?;
        copy_legacy_refresh_tokens(legacy_db, &mut tx).await?;
        copy_legacy_access_tokens(legacy_db, &mut tx).await?;
        sqlx::query(
            "INSERT INTO oauth_meta(key,value) VALUES('legacy_import_complete','1') ON CONFLICT(key) DO UPDATE SET value='1'",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn legacy_table_exists(db: &sqlx::SqlitePool, table: &str) -> Result<bool, sqlx::Error> {
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1")
            .bind(table)
            .fetch_optional(db)
            .await?;
    Ok(exists.is_some())
}

async fn copy_legacy_clients(
    source: &sqlx::SqlitePool,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), sqlx::Error> {
    if !legacy_table_exists(source, "oauth_clients").await? {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT client_id,client_secret_hash,redirect_uris,token_endpoint_auth_method,client_name,created_at FROM oauth_clients",
    )
    .fetch_all(source)
    .await?;
    for row in rows {
        sqlx::query(
            "INSERT OR IGNORE INTO oauth_clients(client_id,client_secret_hash,redirect_uris,token_endpoint_auth_method,client_name,created_at) VALUES(?,?,?,?,?,?)",
        )
        .bind(row.try_get::<String, _>("client_id")?)
        .bind(row.try_get::<Option<String>, _>("client_secret_hash")?)
        .bind(row.try_get::<String, _>("redirect_uris")?)
        .bind(row.try_get::<String, _>("token_endpoint_auth_method")?)
        .bind(row.try_get::<Option<String>, _>("client_name")?)
        .bind(row.try_get::<String, _>("created_at")?)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn copy_legacy_codes(
    source: &sqlx::SqlitePool,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), sqlx::Error> {
    if !legacy_table_exists(source, "oauth_codes").await? {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT code_hash,client_id,redirect_uri,code_challenge,resource,scope,expires_at,used FROM oauth_codes",
    )
    .fetch_all(source)
    .await?;
    for row in rows {
        sqlx::query(
            "INSERT OR IGNORE INTO oauth_codes(code_hash,client_id,redirect_uri,code_challenge,resource,scope,expires_at,used) VALUES(?,?,?,?,?,?,?,?)",
        )
        .bind(row.try_get::<String, _>("code_hash")?)
        .bind(row.try_get::<String, _>("client_id")?)
        .bind(row.try_get::<String, _>("redirect_uri")?)
        .bind(row.try_get::<String, _>("code_challenge")?)
        .bind(row.try_get::<String, _>("resource")?)
        .bind(row.try_get::<String, _>("scope")?)
        .bind(row.try_get::<String, _>("expires_at")?)
        .bind(row.try_get::<i64, _>("used")?)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn copy_legacy_refresh_tokens(
    source: &sqlx::SqlitePool,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), sqlx::Error> {
    if !legacy_table_exists(source, "oauth_refresh_tokens").await? {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT token_hash,client_id,resource,scope,expires_at,revoked FROM oauth_refresh_tokens",
    )
    .fetch_all(source)
    .await?;
    for row in rows {
        sqlx::query(
            "INSERT OR IGNORE INTO oauth_refresh_tokens(token_hash,client_id,resource,scope,expires_at,revoked) VALUES(?,?,?,?,?,?)",
        )
        .bind(row.try_get::<String, _>("token_hash")?)
        .bind(row.try_get::<String, _>("client_id")?)
        .bind(row.try_get::<String, _>("resource")?)
        .bind(row.try_get::<String, _>("scope")?)
        .bind(row.try_get::<String, _>("expires_at")?)
        .bind(row.try_get::<i64, _>("revoked")?)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn copy_legacy_access_tokens(
    source: &sqlx::SqlitePool,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), sqlx::Error> {
    if !legacy_table_exists(source, "oauth_access_tokens").await? {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT token_hash,client_id,resource,scope,expires_at,revoked,created_at FROM oauth_access_tokens",
    )
    .fetch_all(source)
    .await?;
    for row in rows {
        sqlx::query(
            "INSERT OR IGNORE INTO oauth_access_tokens(token_hash,client_id,resource,scope,expires_at,revoked,created_at) VALUES(?,?,?,?,?,?,?)",
        )
        .bind(row.try_get::<String, _>("token_hash")?)
        .bind(row.try_get::<String, _>("client_id")?)
        .bind(row.try_get::<String, _>("resource")?)
        .bind(row.try_get::<String, _>("scope")?)
        .bind(row.try_get::<String, _>("expires_at")?)
        .bind(row.try_get::<i64, _>("revoked")?)
        .bind(row.try_get::<String, _>("created_at")?)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
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
    protected_resource_metadata_response(format!("{origin}/"), origin, &state.config.scope)
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

    match &state.config.redirect_policy {
        RedirectPolicy::PublicMcp => match url.scheme() {
            "https" => true,
            "http" => matches!(host, "127.0.0.1" | "localhost" | "::1"),
            _ => false,
        },
        RedirectPolicy::Restricted {
            production,
            allowed_hosts,
        } => match url.scheme() {
            "https" => host_allowed(*production, allowed_hosts, host),
            "http" if !*production => {
                matches!(host, "127.0.0.1" | "localhost" | "::1")
                    && (allowed_hosts.is_empty() || host_allowed(false, allowed_hosts, host))
            }
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
        r#"<!doctype html><meta charset="utf-8"><title>Authorize {}</title>
<style>body{{font-family:sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem}}input{{width:100%;padding:.7rem;margin:.4rem 0}}button{{padding:.7rem 1rem}}</style>
<h1>Authorize {} MCP</h1><p>Client: <code>{}</code></p><form method="post" action="/mcp/oauth/authorize">
<input type="hidden" name="client_id" value="{}"><input type="hidden" name="redirect_uri" value="{}">
<input type="hidden" name="code_challenge" value="{}"><input type="hidden" name="code_challenge_method" value="{}">
<input type="hidden" name="state" value="{}"><input type="hidden" name="resource" value="{}"><input type="hidden" name="scope" value="{}">
<label>{} password</label><input type="password" name="password" autofocus required><button type="submit">Authorize</button></form>"#,
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

    if !client
        .redirect_uris
        .iter()
        .any(|uri| uri == &params.redirect_uri)
    {
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
    let root_resource = request.uri().path() == "/";
    let resource = if root_resource {
        format!("{origin}/")
    } else {
        format!("{origin}/mcp")
    };

    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let valid = match token {
        Some(token) => validate_access_token(&state, token, &resource).await,
        None => false,
    };

    if !valid {
        let metadata = if root_resource {
            format!("{origin}/.well-known/oauth-protected-resource")
        } else {
            format!("{origin}/.well-known/oauth-protected-resource/mcp")
        };

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
        OAuthState {
            db,
            config: config(public_url, redirect_policy),
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
        assert!(!valid_redirect_uri(&state, "http://127.0.0.1:1455/cb"));
    }

    #[tokio::test]
    async fn standalone_database_is_created_and_legacy_rows_are_preserved_once() {
        let legacy = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("legacy sqlite");
        for statement in [
            "CREATE TABLE oauth_clients(client_id TEXT PRIMARY KEY,client_secret_hash TEXT,redirect_uris TEXT NOT NULL,token_endpoint_auth_method TEXT NOT NULL,client_name TEXT,created_at TEXT NOT NULL)",
            "CREATE TABLE oauth_codes(code_hash TEXT PRIMARY KEY,client_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,code_challenge TEXT NOT NULL,resource TEXT NOT NULL,scope TEXT NOT NULL,expires_at TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE oauth_refresh_tokens(token_hash TEXT PRIMARY KEY,client_id TEXT NOT NULL,resource TEXT NOT NULL,scope TEXT NOT NULL,expires_at TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE oauth_access_tokens(token_hash TEXT PRIMARY KEY,client_id TEXT NOT NULL,resource TEXT NOT NULL,scope TEXT NOT NULL,expires_at TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL)",
        ] {
            sqlx::query(statement).execute(&legacy).await.unwrap();
        }
        sqlx::query("INSERT INTO oauth_clients VALUES('client-1','secret-hash','[\"https://example.com/cb\"]','client_secret_post','Example','2026-01-01T00:00:00Z')")
            .execute(&legacy).await.unwrap();
        sqlx::query("INSERT INTO oauth_codes VALUES('code-hash','client-1','https://example.com/cb','challenge','https://mcp.example.com/mcp','test','2026-01-01T00:10:00Z',1)")
            .execute(&legacy).await.unwrap();
        sqlx::query("INSERT INTO oauth_refresh_tokens VALUES('refresh-hash','client-1','https://mcp.example.com/mcp','test','2026-02-01T00:00:00Z',1)")
            .execute(&legacy).await.unwrap();
        sqlx::query("INSERT INTO oauth_access_tokens VALUES('access-hash','client-1','https://mcp.example.com/mcp','test','2026-01-01T01:00:00Z',0,'2026-01-01T00:00:00Z')")
            .execute(&legacy).await.unwrap();

        let root = std::env::temp_dir().join(format!("oauth-storage-test-{}", Uuid::new_v4()));
        let path = root.join("nested").join("oauth.db");
        let cfg = config(None, RedirectPolicy::PublicMcp);
        let first = OAuthState::open_migrating_legacy(&path, cfg.clone(), &legacy)
            .await
            .expect("open and import legacy data");
        assert!(path.exists());
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT client_name FROM oauth_clients WHERE client_id='client-1'"
            )
            .fetch_one(&first.db)
            .await
            .unwrap(),
            "Example"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT used FROM oauth_codes WHERE code_hash='code-hash'"
            )
            .fetch_one(&first.db)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT revoked FROM oauth_refresh_tokens WHERE token_hash='refresh-hash'"
            )
            .fetch_one(&first.db)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM oauth_access_tokens WHERE token_hash='access-hash'"
            )
            .fetch_one(&first.db)
            .await
            .unwrap(),
            1
        );
        drop(first);

        // Once cut over, later writes to the legacy application database must not
        // overwrite or re-import into the crate-owned database.
        sqlx::query(
            "UPDATE oauth_clients SET client_name='stale legacy value' WHERE client_id='client-1'",
        )
        .execute(&legacy)
        .await
        .unwrap();
        let reopened = OAuthState::open_migrating_legacy(
            &path,
            config(None, RedirectPolicy::PublicMcp),
            &legacy,
        )
        .await
        .expect("reopen standalone database");
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT client_name FROM oauth_clients WHERE client_id='client-1'"
            )
            .fetch_one(&reopened.db)
            .await
            .unwrap(),
            "Example"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT value FROM oauth_meta WHERE key='legacy_import_complete'"
            )
            .fetch_one(&reopened.db)
            .await
            .unwrap(),
            "1"
        );

        drop(reopened);
        drop(legacy);
        let _ = std::fs::remove_dir_all(root);
    }
}
