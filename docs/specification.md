# Asteroid
This document defines the technical specifications for Asteroid, a minimal OpenID Connect Core 1.0 provider focused on authorization flows and token issuance.

## Specification Overview
Asteroid implements the minimal subset of OpenID Connect Core 1.0 with security enhancements including PKCE, nonce validation, and comprehensive error handling. The system is designed with a clean separation between business logic and storage layers, supporting memory and Redis backends.

## Supported Standards

### Core Standards
- OpenID Connect Core 1.0
- OAuth 2.0 Authorization Framework (RFC 6749) — Authorization Code, Refresh Token, Client Credentials grants
- JSON Web Token (RFC 7519)
- JSON Web Token Profile for OAuth 2.0 Access Tokens (RFC 9068) — JWT access token claims for client_credentials
- JSON Web Key (RFC 7517)
- JSON Web Signature (RFC 7515)

### Security Extensions
- Proof Key for Code Exchange (PKCE) - RFC 7636
- OAuth 2.0 Bearer Token Usage (RFC 6750)
- OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics)

### Additional Standards
- OAuth 2.0 Token Introspection (RFC 7662) - Future
- OAuth 2.0 Token Revocation (RFC 7009) - Future
- Resource Indicators for OAuth 2.0 (RFC 8707) - Future (see `audience` parameter below)
- OpenID Connect Discovery 1.0

## Grant Types

Asteroid supports three OAuth 2.0 grant types, each with a distinct intended use case and token shape.

| Grant Type | Intended Use | Access Token | Refresh Token | ID Token |
| ---------- | ------------ | ------------ | ------------- | -------- |
| `authorization_code` | User-facing sign-in (interactive) | Opaque UUID | Yes | If `openid` scope |
| `refresh_token` | Session extension for user flows | Opaque UUID | Rotated | If `openid` scope |
| `client_credentials` | Machine-to-machine (no user context) | JWT (ES256) | No | No |

Client credentials issue **JWT access tokens** so that resource servers can verify tokens statelessly using the JWKS endpoint, without a network round trip to Asteroid on every request. User-facing flows continue to issue opaque tokens so revocation stays instant via the token store.

The set of grant types a given client may use is controlled by the `allowed_grant_types` field on the Client entity. Empty means the pre-client-credentials default of `["authorization_code", "refresh_token"]` for backward compatibility; a client wishing to use client_credentials must list it explicitly.

## Endpoints

### Discovery Endpoint
- **Path**: `/.well-known/openid-configuration`
- **Method**: GET
- **Description**: Returns OpenID Connect discovery document
- **Authentication**: None required

**Response Example**:
```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "jwks_uri": "https://auth.example.com/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "access_token_signing_alg_values_supported": ["ES256"],
  "scopes_supported": ["openid"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "response_modes_supported": ["query"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "scope", "client_id", "token_use", "jti"]
}
```

### Authorization Endpoint
- **Path**: `/authorize`
- **Method**: GET
- **Description**: OAuth 2.0 authorization endpoint with OIDC extensions

**Required Parameters**:
- `response_type`: Must be "code"
- `client_id`: Registered client identifier
- `redirect_uri`: Must exactly match registered URI
- `scope`: Must include "openid"
- `state`: CSRF protection parameter (required)

**Optional Parameters**:
- `nonce`: ID Token replay protection
- `code_challenge`: PKCE code challenge (base64url-encoded)
- `code_challenge_method`: Must be "S256" if code_challenge provided

**Success Response**:
- HTTP 302 redirect to `redirect_uri` with `code` and `state` parameters

**Error Response**:
- HTTP 302 redirect to `redirect_uri` with error parameters
- HTTP 400 for invalid client or redirect URI

### Token Endpoint
- **Path**: `/token`
- **Method**: POST
- **Content-Type**: `application/x-www-form-urlencoded`
- **Authentication**: Client secret required

**Authorization Code Grant Parameters**:
- `grant_type`: Must be "authorization_code"
- `code`: Authorization code from authorization endpoint
- `redirect_uri`: Must match authorization request
- `client_id`: Client identifier
- `client_secret`: Client secret
- `code_verifier`: PKCE code verifier (if PKCE used)

**Refresh Token Grant Parameters**:
- `grant_type`: Must be "refresh_token"
- `refresh_token`: Valid refresh token
- `client_id`: Client identifier
- `client_secret`: Client secret

**Client Credentials Grant Parameters** (RFC 6749 §4.4):
- `grant_type`: Must be "client_credentials"
- `client_id`: Client identifier
- `client_secret`: Client secret (public clients are rejected — client_credentials requires a confidential client)
- `scope`: Space-separated requested scopes; each scope must be present in the client's `allowed_scopes`
- `audience`: Target resource server identifier; must be present in the client's `allowed_audiences`. Optional if the client has exactly one entry in `allowed_audiences` (used as default); required if the client has multiple

The client's `allowed_grant_types` must include `"client_credentials"` or the request is rejected with `unauthorized_client`. Client authentication follows the same rules as other grants (`client_secret_post` or `client_secret_basic`).

**Success Response (authorization_code / refresh_token)**:
```json
{
  "access_token": "uuid-v4-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "uuid-v4-refresh-token",
  "id_token": "jwt-id-token",
  "scope": "openid"
}
```

**Success Response (client_credentials)**:
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}
```

No `refresh_token` is issued for the client credentials grant (per RFC 6749 §4.4.3 — the client can simply request a new access token). No `id_token` is issued because no user context exists.

### JWKS Endpoint
- **Path**: `/jwks.json`
- **Method**: GET
- **Description**: JSON Web Key Set for ID Token verification
- **Authentication**: None required

**Response Example**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "id-token-key-id",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "use": "sig",
      "alg": "ES256",
      "kid": "access-token-key-id",
      "crv": "P-256",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate"
    }
  ]
}
```

## Token Formats

### Access Token (Authorization Code / Refresh Token flows)
- **Format**: UUID v4 (opaque)
- **Lifetime**: 1 hour
- **Storage**: Stored in backend with metadata (client_id, user_id, scope, expires_at)
- **Scope**: Contains granted scopes
- **Validation**: Consumers cannot validate directly; introspection endpoint planned (RFC 7662)

### Access Token (Client Credentials flow)
- **Format**: JWT (JSON Web Token), RFC 9068 profile
- **Algorithm**: ES256, signed with its active key and published via `/jwks.json`
- **Lifetime**: 1 hour
- **Storage**: Stateless — not persisted server-side; revocation waits for `exp`
- **Validation**: Resource server verifies the JWT signature against the JWKS endpoint locally, with no round trip to Asteroid on the hot path

**Access Token Claims (client_credentials)**:
```json
{
  "iss": "https://auth.example.com",
  "sub": "client-id",
  "aud": "resource-server-id",
  "exp": 1234567890,
  "iat": 1234567890,
  "scope": "api:read api:write",
  "client_id": "client-id",
  "token_use": "access",
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

- `sub` — equal to `client_id` when there is no user (RFC 9068 §2.2)
- `aud` — the target resource server; validated at issuance against `allowed_audiences` and again at consumption by the resource server
- `scope` — space-separated list of granted scopes (subset of the client's `allowed_scopes`)
- `token_use` — always `"access"`; identifies the JWT as an access token
- `jti` — unique token identifier; reserved for future revocation via a `jti` denylist

ID Tokens use RS256 and JWT access tokens use ES256. Both active public keys are published via JWKS. Consumers distinguish token purposes by their validation context and claims.

### Refresh Token
- **Format**: UUID v4
- **Lifetime**: 30 days
- **Usage**: Single-use (deleted after refresh)
- **Rotation**: New refresh token issued on each use

### ID Token
- **Format**: JWT (JSON Web Token)
- **Algorithm**: RS256
- **Lifetime**: 1 hour
- **Claims**: Standard OIDC claims

**ID Token Claims**:
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-unique-id",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234567890,
  "auth_time": 1234567800,
  "nonce": "request-nonce"
}
```

### Authorization Code
- **Format**: UUID v4
- **Lifetime**: 5 minutes
- **Usage**: Single-use (deleted after token exchange)
- **Storage**: Contains authorization context

## Security Features

### PKCE (Proof Key for Code Exchange)
- **Support**: RFC 7636 compliant
- **Methods**: S256 only (plain method rejected)
- **Validation**: SHA256 hash verification
- **Enforcement**: Optional but recommended

### Nonce Validation
- **Purpose**: ID Token replay protection
- **Storage**: Per-client namespacing
- **TTL**: 7 minutes (auth code lifetime + 2 minute buffer)
- **Implementation**: Atomic operations prevent race conditions

### Redirect URI Validation
- **Policy**: Exact string match required (RFC 6749 Section 3.1.2.3)
- **Implementation**: Byte-for-byte string comparison
- **Normalization**: Prevented by avoiding URL parsing
- **Security**: Protects against URL normalization attacks
  - Path traversal: `http://localhost/callback/../admin`
  - Double slashes: `http://localhost//callback`
  - Encoding variations: `http://localhost/callback%2F`
  - Case manipulation: `http://LOCALHOST/callback`
- **Wildcards**: Not supported

### State Parameter
- **Requirement**: Mandatory for CSRF protection
- **Validation**: Echoed back unchanged
- **Implementation**: No server-side storage required

## Storage Architecture

### Supported Backends
- **Memory**: In-memory maps with cleanup goroutines
- **Redis**: JSON serialization with TTL

### Build Tags
- `//go:build memory || !redis` - Memory backend (default fallback)
- `//go:build redis` - Redis backend build

### Data Models

#### File-Based Models
Loaded from YAML files at startup and cached in memory.

**Client Entity** (`data/clients.yaml`):
```go
type Client struct {
    ID                      string   `yaml:"id"`
    Secret                  string   `yaml:"secret"`
    RedirectURIs            []string `yaml:"redirect_uris"`
    Name                    string   `yaml:"name"`
    TokenEndpointAuthMethod string   `yaml:"token_endpoint_auth_method"`
    ClientType              string   `yaml:"client_type"` // "confidential" or "public"

    // Grant / scope / audience policy — enforced at the token endpoint
    AllowedGrantTypes       []string `yaml:"allowed_grant_types"` // e.g. ["authorization_code", "refresh_token"] or ["client_credentials"]
    AllowedScopes           []string `yaml:"allowed_scopes"`      // scope allowlist; requested scopes must be a subset
    AllowedAudiences        []string `yaml:"allowed_audiences"`   // audience allowlist for client_credentials grant
}
```

**Policy field defaults (backward compatibility)**:
- `AllowedGrantTypes` empty → `["authorization_code", "refresh_token"]` (pre-existing clients keep working unchanged)
- `AllowedScopes` empty → `["openid"]` for `authorization_code` clients; empty means "no scopes granted" for `client_credentials` clients (which fails safely)
- `AllowedAudiences` empty → allowed only for clients that do not use `client_credentials`; a `client_credentials` request against such a client is rejected with `invalid_request`

The policy is checked at every token request. Requested `scope` and `audience` values that are not on the client's allowlist are rejected with `invalid_scope` or `invalid_target` respectively, before any token is minted.

**User Entity** (`data/users.yaml`):
```go
type YAMLUser struct {
    ID           string         `yaml:"id"`
    Email        string         `yaml:"email"`
    PasswordHash string         `yaml:"password_hash"`
    CreatedAt    string         `yaml:"created_at"`
    Claims       map[string]any `yaml:"claims,omitempty"` // Additional OIDC claims
}
```

#### Persistent Models
Stored in configured backend (memory or Redis) with automatic expiration.

**Authorization Code Entity**:
```go
type AuthCode struct {
    Code                string    `json:"code"`
    ClientID            string    `json:"client_id"`
    UserID              string    `json:"user_id"`
    RedirectURI         string    `json:"redirect_uri"`
    CodeChallenge       string    `json:"code_challenge"`
    CodeChallengeMethod string    `json:"code_challenge_method"`
    Scope               string    `json:"scope"`
    State               string    `json:"state"`
    Nonce               string    `json:"nonce"`
    ExpiresAt           time.Time `json:"expires_at"`
}
```

**Access Token Entity**:
```go
type AccessToken struct {
    Token     string    `json:"token"`
    ClientID  string    `json:"client_id"`
    UserID    string    `json:"user_id"`
    Scope     string    `json:"scope"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

**Refresh Token Entity**:
```go
type RefreshToken struct {
    Token     string    `json:"token"`
    ClientID  string    `json:"client_id"`
    UserID    string    `json:"user_id"`
    Scope     string    `json:"scope"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

## Error Handling

### Authorization Endpoint Errors
- `invalid_request`: Missing or malformed parameters
- `unauthorized_client`: Client not authorized
- `access_denied`: User denied access
- `unsupported_response_type`: Response type not supported
- `invalid_scope`: Requested scope invalid
- `server_error`: Internal server error

### Token Endpoint Errors
- `invalid_request`: Missing or malformed parameters (also: `client_credentials` without a resolvable audience)
- `invalid_client`: Client authentication failed, or public client attempted `client_credentials`
- `invalid_grant`: Authorization grant invalid
- `unauthorized_client`: Client not authorized for the requested grant type (grant not in the client's `allowed_grant_types`)
- `unsupported_grant_type`: Grant type not supported by the server
- `invalid_scope`: Requested scope invalid or not in the client's `allowed_scopes`
- `invalid_target`: Requested audience not in the client's `allowed_audiences` (RFC 8707 error code, reused here)

## Configuration

### Environment Variables
- `OIDC_ISSUER`: OIDC issuer URL (default: `http://localhost:8880`)

**Redis Configuration** (when using Redis backend):
- `REDIS_ADDR`: Redis server address (default: `localhost:6379`)
- `REDIS_PASSWORD`: Redis password (optional)
- `REDIS_DB`: Redis database number (default: `0`)

### Data Loading
- **Clients**: `data/clients.yaml`
- **Users**: `data/users.yaml`

### Key Management
- **Algorithms**: RSA SHA-256 (RS256) for ID Tokens and ECDSA P-256 (ES256) for JWT access tokens
- **Format**: PEM encoded private key
- **Generation**: Automatic key generation at startup
- **Rotation**: Automatic rotation with configurable intervals

## Limitations

### Current Limitations
- User authentication is simplified (fixed to pre-configured users)
- Limited built-in scopes (`openid`); custom scopes are configured per client via `allowed_scopes`
- No UserInfo endpoint
- No dynamic client registration
- Client credentials JWT access tokens are stateless — revocation before `exp` is not supported (planned via `jti` denylist)

### Production Considerations
- Implement proper user authentication
- Configure TLS/SSL termination
- Set up monitoring and logging
- Implement rate limiting
- Configure database connection pooling
- Set up backup and disaster recovery

## Future Enhancements

### Planned Features
- Additional client authentication methods (client_secret_jwt)
- Extended scope support (profile, email, address, phone)
- Token introspection and revocation endpoints (RFC 7662, RFC 7009)
- `jti` denylist for JWT access token revocation
- RFC 8707 `resource` parameter alignment (currently uses `audience`)
- Administrative APIs for client/user management
- Structured logging with correlation IDs
- Metrics and health check endpoints
- Device authorization grant (RFC 8628)

### Security Enhancements
- Mutual TLS (mTLS) support
- Token binding
- Rich authorization requests
- Pushed authorization requests (PAR)
- JWT-secured authorization requests (JAR)

This specification serves as the authoritative reference for Asteroid's current implementation and planned features.
