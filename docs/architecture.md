# Asteroid Architecture
Asteroid is a minimal OpenID Connect (OIDC) Provider implemented in Go using the Gin framework.

This document outlines the core architecture, supported flows, and the interactions between the client application, the Asteroid provider, and the storage layer.

## OIDC Authorization Code Flow
```mermaid
sequenceDiagram
    participant User as User Agent
    participant Client as Client Application
    participant Asteroid as Asteroid OIDC Provider
    participant Store as Memory Store

    Note over User,Store: Discovery Phase
    Client->>Asteroid: GET /.well-known/openid-configuration
    Asteroid->>Client: OIDC Discovery Document

    Note over User,Store: Authorization Phase
    User->>Client: Login Request
    Client->>User: Redirect to Authorization Endpoint
    User->>Asteroid: GET /authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid&state=...

    Asteroid->>Store: GetClient(client_id)
    Store->>Asteroid: Client Details
    
    alt Valid Client & Redirect URI
        Asteroid->>Store: GetUserByID("user-123")
        Store->>Asteroid: User Details
        Asteroid->>Store: SaveAuthCode(code)
        Store->>Asteroid: Success
        Asteroid->>User: Redirect to redirect_uri?code=...&state=...
        User->>Client: Authorization Code
    else Invalid Request
        Asteroid->>User: Error Response
    end

    Note over User,Store: Token Exchange (Future Implementation)
    Client->>Asteroid: POST /token (code, client_secret)
    Asteroid->>Store: GetAuthCode(code)
    Store->>Asteroid: AuthCode Details
    Asteroid->>Store: DeleteAuthCode(code)
    Asteroid->>Client: ID Token + Access Token

    Note over User,Store: Token Verification
    Client->>Asteroid: GET /jwks.json
    Asteroid->>Client: JSON Web Key Set
    Client->>Client: Verify ID Token Signature
```

## Current Implementation Status

### Implemented
- OIDC Discovery (/.well-known/openid-configuration)
- JWKS endpoint (/jwks.json)
- Authorization endpoint (/authorize)
- Memory-based stores for users, clients, auth codes
- RSA key management
- Authorization code generation and storage

### Future Implementation
- Token endpoint (/token)
- UserInfo endpoint (/userinfo)
- ID Token generation (JWT)
- Access token validation
- Refresh token support
- Proper user authentication
- Client secret validation
- PKCE support
- Scope handling beyond 'openid'

## Security Considerations

- Fixed user authentication (user-123) - for development only
- Auth codes expire after 5 minutes
- Automatic cleanup of expired auth codes
- RSA key-based JWT signing
- Redirect URI validation against registered URIs