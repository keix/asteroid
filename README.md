# Asteroid
An OpenID Connect Core 1.0 Provider implementation written in Go using the Gin framework.

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

The key must be stored securely and should never be committed to version control. For production environments, a secure key management service (KMS) is strongly recommended.

## License
Copyright KEI SAWAMURA 2025.  
Asteroid is licensed under the MIT License. Copying, and modifying is encouraged and appreciated.
