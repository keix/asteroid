# Asteroid
An OpenID Connect Core 1.0 Provider implementation written in Go using the Gin framework.

## Why Asteroid?
Asteroid is composed of small, independent components that work together loosely — much like a cluster of asteroids forming a stable system.

This design aligns with the UNIX philosophy: each unit does one thing well, keeping the whole system simple, transparent, and easy to understand.

## Prerequisites
- Go 1.24 or later (Tested with Go 1.24.6)
- OpenSSL (for generating RSA private keys)

## Running Locally
1. Generate RSA private key:
```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
```

2. Build the server:
```bash
go mod tidy
go build -o bin/asteroid ./cmd/server
```

3. Start the server:
```bash
./bin/asteroid
```

The server will start on port 8880 by default.

## Configuration
Asteroid is configured using environment variables:

| Variable                | Description           | Default                 |
| ----------------------- | --------------------- | ----------------------- |
| `OIDC_ISSUER`           | Issuer URL            | `http://localhost:8880` |
| `OIDC_PRIVATE_KEY_PATH` | RSA private key (PEM) | `./keys/private.pem`    |

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

## UserInfo Endpoint (Extension Point)
Asteroid does not include a built-in userinfo endpoint by default. In real-world deployments, user attributes are typically provided by external systems — not embedded inside the OIDC provider.

The default implementation loads initial users from a YAML file into in-memory storage. For production use, you can replace this with a custom UserStore implementation that retrieves users from your existing identity system, database, or external API.

The OIDC core remains unchanged.  
Simply provide your own UserStore, and Asteroid will use it automatically.

For example, you may replace it with a proxy-backed implementation:
```
stores.User = external.NewUserProxy(apiURL, httpClient)
```

## Storage
A storage backend can be selected at build time:

```
go build -tags [memory, redis, dynamodb] -o bin/asteroid ./cmd/server
```

Redis provides fast, TTL-based persistence and is recommended for production-grade authorization code and token storage.

## Docker
Asteroid is not Dockerized by default. A simple Dockerfile is included for convenience, but it is optional and can be extended as needed.

Example configurations for Redis and DynamoDB Local are available under `examples/docker/`.

## Security Note
Asteroid loads the RSA private key once at startup and keeps it in memory.

The key must be stored securely and should never be committed to version control. Asteroid provides an interface for persisting newly generated keys during rotation.

In development environments, keys can be written to a local file. For production deployments, we highly recommend storing rotated keys in a secure Key Management Service (KMS).

In addition, Asteroid should not be exposed directly to the public internet.  
We recommend placing it behind a reverse proxy:

- **nginx (via unix domain socket)**  
  Provides optimal isolation, no TCP surface, and keeps TLS termination outside the Asteroid process.

- **AWS ALB (directly in front of Asteroid)**  
  A clean, minimal setup where TLS termination and access control are fully handled by ALB, keeping Asteroid isolated from direct exposure and free from transport-layer concerns.

By delegating TLS termination, rate limiting, and access policies to the upstream layer, the Asteroid binary can remain small, simple, and secure—consistent with its UNIX-inspired design philosophy.

## License
Copyright KEI SAWAMURA 2025 (a.k.a keix)  
Asteroid is licensed under the MIT License. Copying, and modifying is encouraged and appreciated.
