# Testing Philosophy

Asteroid's tests follow UNIX principles: each test does one thing well, tests are composable, and complexity emerges from simple interactions between well-tested units.

## Test Organization

### Unit Tests
Located alongside code with `*_test.go` suffix.
- **Purpose**: Test individual functions in isolation
- **Coverage**: Authorization, token exchange, HTTP parsing
- **Status**: 30 tests implemented

### Integration Tests  
Located in this directory for cross-package validation.
- **Purpose**: Test component interactions end-to-end
- **Coverage**: Complete OIDC flows, storage backends
- **Status**: Core OIDC flow implemented

### End-to-End Tests
Future implementation for full system validation.
- **Purpose**: Test complete application behavior
- **Coverage**: External service integration, performance
- **Status**: Planned

## Running Tests

```bash
# Unit tests (recommended)
go test ./internal/oidc/authorize/
go test ./internal/oidc/token/

# Integration tests
go test ./test/

# Avoid ./... due to build tag conflicts
```

## Current Integration Coverage

### OIDC Authorization Flow (`integration_test.go`)
Complete flow testing authorization → token exchange → refresh:
- Authorization endpoint with state/nonce validation
- Token endpoint with JWT signing verification  
- JWKS endpoint for public key distribution

Each step validates the next, ensuring the complete flow works as one coherent system.

## Test Data

```
../data/
├── clients.yaml     # Test OAuth clients
└── users.yaml      # Test user profiles
```

Test data is minimal, reusable, and reflects real-world scenarios without unnecessary complexity.