# oauth

A small Rust OAuth 2.1 authorization server for MCP HTTP endpoints.

It provides the OAuth pieces an MCP server commonly needs without requiring you to implement the protocol flow yourself.

## Features

- OAuth authorization-server metadata
- MCP protected-resource metadata
- Dynamic Client Registration
- Authorization Code flow with PKCE `S256`
- Refresh tokens
- Bearer-token validation for MCP routes
- SQLite-backed clients, authorization codes, access tokens, and refresh tokens
- Configurable redirect-URI policy
- Optional external client metadata resolution

## Add it to your project

The crate is currently consumed directly from Git:

```toml
[dependencies]
oauth = { git = "https://github.com/darkautism/oauth.git" }
```

It uses Axum 0.8 and SQLx 0.8 with SQLite.

## Database

Create the OAuth tables before serving requests. A ready-to-use schema is included at:

```text
migrations/0001_oauth.sql
```

The crate stores only hashes of access tokens, refresh tokens, authorization codes, and confidential-client secrets.

## Minimal setup

```rust
use std::sync::Arc;

use oauth::{OAuthConfig, OAuthState, RedirectPolicy, TokenPrefixes};

let oauth_state = Arc::new(OAuthState::new(
    sqlite_pool,
    OAuthConfig {
        service_name: "My MCP".into(),
        scope: "my-mcp".into(),

        // Prefer an explicit public URL in production.
        public_url: Some("https://mcp.example.com".into()),

        // Password shown by the built-in authorization form.
        oauth_password: Some("replace-me".into()),

        // Used only when public_url is not set.
        default_host: "127.0.0.1:8080".into(),

        // Controls generated client/code/token prefixes.
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
));
```

Mount the OAuth routes into your Axum application:

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

Apply `require_mcp_auth` only to the MCP routes that require a bearer token:

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

If some client IDs should be resolved outside the local `oauth_clients` table, implement `ExternalClientResolver`:

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
let oauth_state = OAuthState::new(sqlite_pool, config)
    .with_external_client_resolver(Arc::new(MyResolver));

let oauth_state = Arc::new(oauth_state);
```

The resolver is consulted only when a client ID is not found in the local database.

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
| `client_id_metadata_document_supported` | Advertise external client metadata support |

## Current storage and token lifetimes

The current implementation uses SQLite and fixed lifetimes:

- authorization code: 10 minutes
- access token: 1 hour
- refresh token: 30 days
