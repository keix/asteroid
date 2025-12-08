# Asteroid
An OpenID Connect Core 1.0 Provider implementation written in Go using the Gin framework.

## Why Asteroid?
Asteroid is composed of small, independent components that work together loosely — much like a cluster of asteroids forming a stable system.

This design aligns with the UNIX philosophy: each unit does one thing well, keeping the whole system simple, transparent, and easy to understand.

## Requirements
Asteroid needs only a compiler; Go 1.24+ is sufficient.  
The recommended setup is the reproducible Nix development shell:

```
nix develop
```

Inside the Nix shell, Redis is available by default. It is a pure Go binary, with no runtime dependencies or container requirements.

## Running the Server
1. Build the server:
```bash
go mod tidy
go build -o bin/asteroid ./cmd/server
```

2. Start the server:
```bash
./bin/asteroid
```

The server will start on port 8880 by default and automatically generate signing keys as needed.

## Configuration
Asteroid is configured using environment variables:

| Variable                | Description           | Default                 |
| ----------------------- | --------------------- | ----------------------- |
| `OIDC_ISSUER`           | Issuer URL            | `http://localhost:8880` |

For production deployments, be sure to read the Security Note below.

## Available Endpoints
For detailed flow diagrams and architecture documentation, see [`docs/architecture.md`](docs/architecture.md).

### OpenID Connect Discovery
```
GET /.well-known/openid-configuration
```

### Authorization
```
GET /authorize
```

Implements the authorization code flow for a pre-seeded test user.  

Query parameters:
- `client_id` — must be a registered client
- `redirect_uri` — must match one of the client's allowed URIs
- `response_type` — only `code` is supported
- `scope` — must include `openid` for OpenID Connect flows
- `state` — optional value echoed back on redirect
- `nonce` — optional nonce value included in ID Token

Returns HTTP redirects with `code` (and `state`) appended to the provided `redirect_uri`, or an error response if validation fails.

### Token Exchange
```
POST /token
```

Exchanges authorization codes for access and refresh tokens, or refreshes existing tokens.

Form parameters:
- `grant_type` — `authorization_code` or `refresh_token`
- `client_id` — registered client identifier
- `client_secret` — client authentication secret

For authorization code grant:
- `code` — authorization code from `/authorize` endpoint
- `redirect_uri` — must match the original authorization request

For refresh token grant:
- `refresh_token` — valid refresh token

Returns JSON with `access_token`, `token_type`, `expires_in`, `refresh_token`, `scope`, and `id_token` (for OpenID Connect flows).

The `id_token` is a signed JWT containing user identity claims, compliant with OpenID Connect Core 1.0 specification.

### JSON Web Key Set (JWKS)
```
GET /jwks.json
```

Public JWK used by clients and resource servers to validate tokens.

## User Authentication and Information
Asteroid does not perform user authentication.  
The authenticated user is provided by the upstream layer via:

```
X-Authenticated-User: <subject>
```

Asteroid resolves user information on demand through a pluggable provider:

```go
// Development
userinfoProvider := source.NewYAMLProvider("./data/users.yaml")

// Production
userinfoProvider := source.NewHTTPProvider(apiURL, httpClient)
```

The provider acts as the trust boundary:  
- If the user no longer exists - token issuance is denied  
- No user data is stored or cached inside Asteroid  
- Any identity backend can be integrated by implementing the interface

This keeps OIDC authorization pure, independent, and decoupled from your authentication system.

## Storage
Asteroid includes an in-memory store by default.  
If you want to use Redis, build with:
```
go build -tags redis -o bin/asteroid ./cmd/server
```

Redis is recommended for production-grade authorization code and token storage.

## Docker
Asteroid is not dockerized by default — it runs as a small, self-contained Go binary.

For developers who use Redis as storage backend, minimal Docker Compose
examples are available under:

```
examples/docker/
```

These examples include only the essential services needed for local development:

- Redis — fast, TTL-based store for authorization codes and tokens

The examples contain only the essentials — nothing more.

## Security Note
Asteroid automatically generates signing keys at startup and handles key rotation transparently. Keys are never stored in version control and are managed entirely through the built-in key management system.

In development environments, generated keys are persisted to local files for convenience. For production deployments, we highly recommend configuring a Key Management Service (KMS) through the persister interface for secure key storage and rotation.

In addition, Asteroid should not be exposed directly to the public internet.  
We recommend placing it behind a reverse proxy:

- **nginx (via unix domain socket)**  
  Provides optimal isolation, no TCP surface, and keeps TLS termination outside the Asteroid process.

- **AWS ALB (directly in front of Asteroid)**  
  A clean, minimal setup where TLS termination and access control are fully handled by ALB, keeping Asteroid isolated from direct exposure and free from transport-layer concerns.

By delegating TLS termination, rate limiting, and access policies to the upstream layer, the Asteroid binary can remain small, simple, and secure—consistent with its UNIX-inspired design philosophy.

Asteroid runs on HTTP by design. In development, running the issuer over http://localhost is fully supported and expected.

However, in production, all OIDC clients MUST access the issuer over HTTPS, with TLS termination handled by your upstream reverse proxy (nginx, Envoy, ALB, etc.).

This ensures the Asteroid binary remains transport-layer agnostic while still complying with OpenID Connect security requirements.

## License
Copyright KEI SAWAMURA 2025 (a.k.a keix)  
Asteroid is licensed under the MIT License. Copying, and modifying is encouraged and appreciated.
