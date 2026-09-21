# oauth

Shared OAuth 2.1 / MCP authorization-server crate used by `pc` and `LazyTeam`.

It owns the common MCP OAuth surface: discovery metadata, dynamic client registration,
authorization-code + PKCE, refresh tokens, bearer validation, and MCP auth middleware.
Applications provide deployment policy through `OAuthConfig`; optional external client
metadata (for example LazyTeam CIMD) is supplied through `ExternalClientResolver`.

The crate deliberately does not own an application's MCP tool server or sandbox.
