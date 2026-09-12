# Go OIDC RBAC

A work-in-progress Go web application exploring OpenID Connect
authentication with Authentik and role-based access control.

## Current status

- HTTP server with structured logging through slog
- Separate public and authentication-protected route groups
- OIDC provider discovery and login-flow scaffolding
- Placeholder homepage, admin page, and authentication callback

Authentication and authorization are not functional yet.

## Planned work

- Complete authorization-code flow with PKCE, state, and nonce validation
- Verify ID tokens and establish server-side sessions
- Add concurrency-safe storage and expiration for pending logins
- Implement admin-role enforcement
- Add tests for authentication and authorization behavior
- Add graceful shutdown and server timeouts

## Design

Public routes handle the homepage, login, and OIDC callback.
Other routes pass through authentication middleware, with an
additional role check planned for the admin page.
