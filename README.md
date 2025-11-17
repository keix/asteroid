# Asteroid
A minimal OpenID Connect (OIDC) Provider implementation written in Go using the Gin framework.

## Prerequisites
- Go 1.22 or later
- OpenSSL (for generating RSA private keys)

## Building
```bash
go mod tidy
go build -o bin/asteroid ./cmd/server
```

## Running
1. Generate RSA private key:
```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
```

2. Start the server:
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

### OpenID Connect Discovery
```
GET /.well-known/openid-configuration
```

Returns metadata such as:
- issuer
- authorization endpoint
- token endpoint
- JWKS URI
- supported response types
- supported signing algorithms

### JSON Web Key Set (JWKS)
```
GET /jwks.json
```

Public JWK used by clients and resource servers to validate tokens.

## Docker
Asteroid is not Dockerized by default.  
It is intended as a minimal OIDC provider implementation in Go.

A simple Dockerfile is included for convenience, but it is optional and can be extended as needed.

## Storage
Asteroid does not enforce any particular storage backend.

The internal stores (users, clients, keys, auth codes) are defined as interfaces, and you can provide any implementation by passing your own struct instances.

A DynamoDB Local example is provided under `examples/ddb/`, demonstrating how to wire custom stores into the server. 

This is only a sample and not part of the core implementation.