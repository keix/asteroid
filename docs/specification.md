# Asteroid
This document defines the technical specifications for Asteroid, a minimal OpenID Connect Core 1.0 provider focused on authorization flows and token issuance.

## Specification Overview
Asteroid implements the minimal subset of OpenID Connect Core 1.0 with security enhancements including PKCE, nonce validation, and comprehensive error handling. The system is designed with a clean separation between business logic and storage layers, supporting memory and Redis backends.

## Supported Standards

### Core Standards
- OpenID Connect Core 1.0
- OAuth 2.0 Authorization Framework (RFC 6749)
- JSON Web Token (RFC 7519)
- JSON Web Key (RFC 7517)
- JSON Web Signature (RFC 7515)

### Security Extensions
- Proof Key for Code Exchange (PKCE) - RFC 7636
- OAuth 2.0 Bearer Token Usage (RFC 6750)
- OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics)

### Additional Standards
- OAuth 2.0 Token Introspection (RFC 7662) - Future
- OAuth 2.0 Token Revocation (RFC 7009) - Future
- OpenID Connect Discovery 1.0

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
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"],
  "scopes_supported": ["openid"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "response_modes_supported": ["query"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce"]
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

**Success Response**:
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
      "kty": "EC",
      "use": "sig",
      "alg": "ES256",
      "kid": "key-id",
      "crv": "P-256",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate"
    }
  ]
}
```

## Token Formats

### Access Token
- **Format**: UUID v4
- **Lifetime**: 1 hour
- **Storage**: Stored in backend with metadata
- **Scope**: Contains granted scopes

### Refresh Token
- **Format**: UUID v4
- **Lifetime**: 30 days
- **Usage**: Single-use (deleted after refresh)
- **Rotation**: New refresh token issued on each use

### ID Token
- **Format**: JWT (JSON Web Token)
- **Algorithm**: ES256
- **Lifetime**: 15 minutes
- **Claims**: Standard OIDC claims

**ID Token Claims**:
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-unique-id",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234567890,
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

**Client Entity**:
```go
type Client struct {
    ID                      string   `json:"id"`
    Secret                  string   `json:"secret"`
    RedirectURIs            []string `json:"redirect_uris"`
    Name                    string   `json:"name"`
    TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
    ClientType              string   `json:"client_type"` // "confidential" or "public"
}
```

**User Entity**:
```go
type YAMLUser struct {
    Sub    string                 `yaml:"sub"`
    Email  string                 `yaml:"email"`
    Claims map[string]interface{} `yaml:"claims"`
}
```

**Authorization Code Entity**:
```go
type AuthCode struct {
    Code                 string    `json:"code"`
    ClientID             string    `json:"client_id"`
    UserID               string    `json:"user_id"`
    RedirectURI          string    `json:"redirect_uri"`
    Scope                string    `json:"scope"`
    State                string    `json:"state"`
    Nonce                string    `json:"nonce"`
    CodeChallenge        string    `json:"code_challenge"`
    CodeChallengeMethod  string    `json:"code_challenge_method"`
    ExpiresAt            time.Time `json:"expires_at"`
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
- `invalid_request`: Missing or malformed parameters
- `invalid_client`: Client authentication failed
- `invalid_grant`: Authorization grant invalid
- `unauthorized_client`: Client not authorized for grant type
- `unsupported_grant_type`: Grant type not supported
- `invalid_scope`: Requested scope invalid

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
- **Keys**: Automatically generated in `keys/` directory

### Key Management
- **Algorithm**: ECDSA P-256 for ES256 signatures
- **Format**: PEM encoded private key
- **Generation**: Automatic key generation at startup
- **Rotation**: Automatic rotation with configurable intervals

## Limitations

### Current Limitations
- User authentication is simplified (fixed to pre-configured users)
- Limited scope support (only "openid")
- No UserInfo endpoint
- No dynamic client registration

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
- Token introspection and revocation endpoints
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
