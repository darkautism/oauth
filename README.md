# oauth

A small Rust OAuth 2.1 authorization server for MCP HTTP endpoints.

It provides the OAuth pieces an MCP server commonly needs without making the application own OAuth tables, migrations, or token storage.

## Features

- OAuth authorization-server metadata
- MCP protected-resource metadata
- Dynamic Client Registration
- Client ID Metadata Documents (CIMD) with public-endpoint SSRF protection
- Authorization Code flow with PKCE `S256`
- Refresh tokens
- Bearer-token validation for MCP routes
- Private SQLite storage managed by the crate
- Automatic database creation and schema migration
- Configurable redirect-URI policy
- Optional external client metadata resolution

## Add it to your project

```toml
[dependencies]
oauth = { git = "https://github.com/darkautism/oauth.git" }
```

The crate uses Axum 0.8 internally for its HTTP routes.

## Quick start

Choose where OAuth should keep its private database:

```rust
use std::sync::Arc;

use oauth::{OAuthConfig, OAuthState, RedirectPolicy, TokenPrefixes};

let oauth_state = Arc::new(
    OAuthState::open(
        "./data/oauth.db",
        OAuthConfig {
            service_name: "My MCP".into(),
            scope: "my-mcp".into(),
            public_url: Some("https://mcp.example.com".into()),
            oauth_password: Some("replace-me".into()),
            default_host: "127.0.0.1:8080".into(),
            token_prefixes: TokenPrefixes::new("my"),
            redirect_policy: RedirectPolicy::Restricted {
                production: true,
                allowed_hosts: vec![
                    "chatgpt.com".into(),
                    "*.example.com".into(),
                ],
            },
            client_id_metadata_document_supported: false,
        },
    )
    .await?,
);
```

That path belongs to the OAuth crate. If the directory or database file does not exist, it is created automatically. The crate creates and migrates its own schema; your application does not provide a SQLx pool or maintain OAuth tables.

Mount the OAuth endpoints:

```rust
let app = axum::Router::new()
    .merge(oauth::router(oauth_state.clone()));
```

This adds:

```text
/.well-known/oauth-protected-resource
/.well-known/oauth-protected-resource/mcp
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
/mcp/.well-known/oauth-authorization-server
/mcp/.well-known/openid-configuration
/mcp/oauth/register
/mcp/oauth/authorize
/mcp/oauth/token
```

## Protect an MCP route

Apply `require_mcp_auth` to the MCP routes that require a bearer token:

```rust
use axum::{middleware, Router};

let protected_mcp = Router::new()
    .route_service("/mcp", mcp_service)
    .route_layer(middleware::from_fn_with_state(
        oauth_state.clone(),
        oauth::require_mcp_auth,
    ));

let app = Router::new()
    .merge(oauth::router(oauth_state.clone()))
    .merge(protected_mcp);
```

Requests without a valid token receive `401 Unauthorized` with an MCP-compatible `WWW-Authenticate` header pointing at the protected-resource metadata.

## Storage

The application chooses only the database path:

```rust
OAuthState::open("/var/lib/my-service/oauth.db", config).await?
```

Everything inside that database is private implementation state of this crate. Applications should not query or migrate it themselves.

When a future crate version changes its schema, `OAuthState::open` applies the embedded migrations before serving requests.

## Redirect policies

### `RedirectPolicy::PublicMcp`

Accepts:

- any HTTPS redirect URI
- HTTP only for `localhost`, `127.0.0.1`, or `::1`

### `RedirectPolicy::Restricted`

Accepts only configured HTTPS hosts in production.

Wildcard entries such as `*.example.com` match subdomains, not the apex domain itself.

In non-production mode, an empty allow-list permits HTTPS redirects and loopback HTTP redirects.

## External client metadata

If some client IDs should be resolved outside the local client store, implement `ExternalClientResolver`:

```rust
use async_trait::async_trait;
use oauth::{ExternalClientResolver, ResolvedClient};

struct MyResolver;

#[async_trait]
impl ExternalClientResolver for MyResolver {
    async fn resolve(
        &self,
        client_id: &str,
    ) -> Result<Option<ResolvedClient>, String> {
        if client_id != "https://client.example.com/metadata.json" {
            return Ok(None);
        }

        Ok(Some(ResolvedClient {
            redirect_uris: vec![
                "https://client.example.com/oauth/callback".into(),
            ],
            auth_method: "none".into(),
            secret_hash: None,
        }))
    }
}
```

Attach it when constructing the state:

```rust
let oauth_state = OAuthState::open("./data/oauth.db", config)
    .await?
    .with_external_client_resolver(Arc::new(MyResolver));

let oauth_state = Arc::new(oauth_state);
```

The resolver is consulted only when a client ID is not found in the crate's local client store.

## Configuration reference

| Field | Purpose |
| --- | --- |
| `service_name` | Display name used by the authorization page and bearer realm |
| `scope` | OAuth scope advertised and issued by the server |
| `public_url` | Canonical externally visible server URL |
| `oauth_password` | Password accepted by the built-in authorization form |
| `default_host` | Fallback host when no public URL is configured |
| `token_prefixes` | Prefixes used for generated IDs and tokens |
| `redirect_policy` | Redirect-URI validation policy |
| `client_id_metadata_document_supported` | Enable and advertise HTTPS Client ID Metadata Documents (CIMD); an external resolver may override resolution |

## Token lifetimes

The current defaults are:

- authorization code: 10 minutes
- access token: 1 hour
- refresh token: 30 days
