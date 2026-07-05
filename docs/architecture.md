# Asteroid
This document outlines the core architecture, layer separation, supported flows, and the interactions between the client application, the Asteroid provider, and the storage layer.

## Architecture Overview
Asteroid follows a clean architecture pattern with clear separation of concerns across three layers: HTTP, Domain, and Storage.

### Layer Responsibilities

#### HTTP Layer (`internal/http/`)
- **Purpose**: HTTP protocol handling and transport concerns
- **Responsibilities**:
  - Request parsing and validation (form data, query parameters)
  - Response formatting (JSON, redirects, error codes)
  - Content-Type handling and HTTP headers
  - HTTP status code mapping
  - Route registration and middleware
- **Principles**:
  - No business logic
  - Thin layer that delegates to domain services
  - Framework-specific code (Gin) isolated here
  - Error handling converts domain errors to HTTP responses

#### Domain Layer (`internal/oidc/`)
- **Purpose**: Core business logic and OIDC protocol implementation
- **Responsibilities**:
  - OIDC Core 1.0 specification compliance
  - OAuth 2.0 authorization flows
  - Security validations (PKCE, nonce, redirect URI)
  - JWT generation and validation
  - Business rule enforcement
  - Protocol-specific error handling
- **Principles**:
  - Framework-agnostic (no HTTP dependencies)
  - Pure business logic functions
  - Dependency injection for stores
  - Domain-specific error types
  - Testable without HTTP infrastructure

#### Storage Layer (`internal/store/`)
- **Purpose**: Data persistence and retrieval abstraction
- **Responsibilities**:
  - Data storage and retrieval operations
  - Entity lifecycle management (TTL, expiration)
  - Storage backend abstraction
  - Transaction and concurrency handling
  - Data serialization/deserialization
- **Principles**:
  - Interface-based design for pluggability
  - Storage backend agnostic
  - Entity models with validation
  - Error handling for storage failures
  - Factory pattern for driver selection

### Cross-Cutting Concerns

#### Configuration (`internal/config/`)
- Build-tag based configuration for different storage backends
- Environment-specific settings
- Storage connection parameters

#### Data Loading (`internal/loader/`)
- YAML-based client data initialization  
- Bootstrap data management for client configuration

#### UserInfo Provider (`internal/userinfo/`)
- User information abstraction layer
- Lazy loading user data on-demand (no startup eager loading)
- Pluggable backends (YAML, HTTP API, etc.)
- Transparent caching support

### Key Architecture Benefits

1. **Testability**: Each layer can be tested independently with mocks
2. **Flexibility**: Storage backends can be swapped without changing business logic
3. **Maintainability**: Clear separation makes code easier to understand and modify
4. **Protocol Compliance**: Domain layer ensures OIDC specification adherence
5. **Scalability**: Interface-based design allows for easy extension

## OIDC Authorization Code Flow
```mermaid
sequenceDiagram
    participant User as User Agent
    participant Client as Client Application
    participant Asteroid as Asteroid
    participant RS as Resource Server

    Note over Client,Asteroid: 1. Discovery
    Client->>Asteroid: GET /.well-known/openid-configuration
    Asteroid-->>Client: OIDC Metadata

    Note over User,Asteroid: 2. Authorization Request
    User->>Client: Login
    Client->>Asteroid: GET /authorize?... (X-Authenticated-User)
    Asteroid-->>Client: Redirect with Authorization Code

    Note over Client,Asteroid: 3. Token Exchange
    Client->>Asteroid: POST /token
    Asteroid-->>Client: ID Token + Access Token

    Note over Client: 4. ID Token Verification
    Client->>Client: Verify ID Token (signature + iss + aud + nonce)

    Note over Client,RS: 5. Resource Access
    Client->>RS: API Request (Bearer <access_token>)
    RS->>Asteroid: GET /jwks.json
    RS->>RS: Verify Access Token
    RS-->>Client: Protected Resource
```

## Current Implementation Status

### Implemented
- **OIDC Discovery** (/.well-known/openid-configuration)
- **JWKS endpoint** (/jwks.json) with RSA and EC public key distribution
- **Authorization endpoint** (/authorize) with comprehensive security validation
- **Token endpoint** (/token) supporting authorization_code and refresh_token grants
- **ID Token generation** (JWT with RS256 signature)
- **Multiple storage backends** (memory, Redis) with build-tag selection
- **PKCE support** (RFC 7636) with S256 method validation
- **Security features**:
  - Nonce replay protection with per-client isolation
  - Exact redirect URI validation (string-based, no normalization)
  - State parameter enforcement for CSRF protection
  - Authorization code expiration (5 minutes)
  - Access token expiration (1 hour)
  - Refresh token rotation
- **Implements a minimal, security-complete subset of OIDC Core 1.0**
- **Comprehensive test suite** with unit tests for all critical paths

### Future Implementation
- **UserInfo endpoint** (/userinfo) - framework exists, not exposed
- **Extended client authentication**: client_secret_jwt, private_key_jwt (client_secret_basic already implemented)
- **Extended scope handling** (profile, email, address, phone)
- **Dynamic user authentication** (currently simplified to pre-configured users)
- **Additional response modes** (fragment, form_post)
- **Token introspection** (RFC 7662) and **revocation** (RFC 7009)
- **Administrative APIs** for client/user management

## ID Token Details

Asteroid generates OIDC-compliant ID tokens as JWTs with the following characteristics:

### JWT Header
```json
{
  "alg": "RS256",
  "kid": "unique-key-id",
  "typ": "JWT"
}
```

### JWT Claims
```json
{
  "iss": "http://localhost:8880",
  "sub": "user-123",
  "aud": "test-client",
  "exp": 1763746030,
  "iat": 1763742430,
  "auth_time": 1763742400,
  "nonce": "client-provided-nonce"
}
```

### Verification
- ID tokens are signed with an RSA private key using RS256
- Public key for verification is available at `/jwks.json` endpoint
- Key ID (`kid`) in JWT header matches the one in JWKS
- Standard JWT validation applies (signature, expiration, issuer, audience)

## Security Considerations

- **User Authentication**: Handled upstream via `X-Authenticated-User` header (no embedded auth)
- **User Existence Validation**: Lazy loading with existence check during token generation
- Auth codes expire after 5 minutes
- Access tokens expire after 1 hour  
- Refresh tokens expire after 30 days
- ID tokens expire after 1 hour
- Automatic cleanup of expired tokens and auth codes
- Client secret validation for token exchange
- RSA SHA-256 signing (RS256) for ID tokens
- Redirect URI validation against registered URIs
- TTL-based token storage with automatic expiration
- JWT signature verification via JWKS endpoint
- Standard OIDC claims in ID tokens (iss, sub, aud, exp, iat, nonce)
