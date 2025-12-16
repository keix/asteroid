# Asteroid
Asteroid's tests follow the UNIX philosophy: each test does one thing well, tests are composable, and complexity emerges from simple interactions between well-tested units.

## Testing Philosophy

### Unit Tests
Located alongside the code with the `*_test.go` suffix.

- **Purpose**: Test individual functions in isolation  
- **Scope**: Authorization logic, token exchange, HTTP parsing  
- **Status**: 30 unit tests implemented

### Integration Tests  
Located in this directory for cross-package validation.

- **Purpose**: Validate interactions between components  
- **Scope**: Complete OIDC authorization code flow, storage backends  
- **Status**: Core integration flow implemented (`oidc_flow_test.go`)

## Running Tests

```bash
# Unit tests (recommended)
go test ./internal/oidc/authorize/
go test ./internal/oidc/token/
go test ./internal/http/token/

# Integration tests
go test ./test/

# Note:
# Avoid using `./...` as build tags are used internally (memory/redis).
```

## Current Integration Coverage

### OIDC Authorization Code Flow (`oidc_flow_test.go`)

Tests the complete flow:

1. **/authorize** — validates client, redirect URI, state, nonce
2. **/token** — exchanges code, validates PKCE and client auth, signs ID Token
3. **/jwks.json** — distributes the public key set
4. **/.well-known/openid-configuration** — exposes issuer metadata
5. **Refresh token flow** — issues new tokens from a valid refresh token

Each step feeds into the next, ensuring the OIDC flow works coherently as a system.

## Test Data

```
/data/
├── clients.yaml   # Test OAuth clients
└── users.yaml     # Test user profiles
```

Test data is minimal, deterministic, and mirrors real-world usage without unnecessary complexity.
