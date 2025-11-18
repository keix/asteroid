# Asteroid
An OpenID Connect (OIDC) Provider implementation written in Go using the Gin framework, intended to be forked as a starter template.

## Prerequisites
- Go 1.22 or later
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

### OpenID Connect Discovery
```
GET /.well-known/openid-configuration
```

### JSON Web Key Set (JWKS)
```
GET /jwks.json
```

Public JWK used by clients and resource servers to validate tokens.

### Authorization
```
GET /authorize
```

Implements the authorization code flow for a pre-seeded test user.  

Query parameters:
- `client_id` — must be a registered client
- `redirect_uri` — must match one of the client's allowed URIs
- `response_type` — only `code` is supported
- `scope` — only `openid` is supported
- `state` — optional value echoed back on redirect

Returns HTTP redirects with `code` (and `state`) appended to the provided `redirect_uri`, or an error response if validation fails.

## Storage
Asteroid defaults to in-memory stores, which are convenient for testing but non-persistent.

All stores (users, clients, keys, auth codes) are defined as interfaces, making it straightforward to plug in a real backend.

A DynamoDB Local example is provided under examples/ddb/.
DynamoDB + Go enables fast, scalable persistence and keeps identity data isolated from the main application.

## Docker
Asteroid is not Dockerized by default.  

A simple Dockerfile is included for convenience, but it is optional and can be extended as needed.

## License
Copyright KEI SAWAMURA 2025.  
Asteroid is licensed under the MIT License. Copying, and modifying is encouraged and appreciated.
