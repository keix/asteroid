# Asteroid
An OpenID Connect Core 1.0–compatible provider written in Go, focused on authorization and token issuance.

## Why Asteroid?
Asteroid is composed of small, independent components that work together loosely — much like a cluster of asteroids forming a stable system.

This design aligns with the UNIX philosophy: each unit does one thing well, keeping the whole system simple, transparent, and easy to understand.

## Requirements
Asteroid needs only a compiler; Go 1.24+ is sufficient.  
The recommended setup is the reproducible Nix development shell:

```
nix develop
```

Inside the Nix shell, Redis is available by default.

## Running the Server
1. Build the server:
```bash
go mod tidy
go build -o bin/asteroid ./cmd/server
```

2. Start the server:
```bash
./bin/asteroid
```

The server will start on port 8880 by default and automatically generate signing keys as needed.

## Configuration
Asteroid is configured using environment variables:

| Variable                | Description           | Default                 |
| ----------------------- | --------------------- | ----------------------- |
| `OIDC_ISSUER`           | Issuer URL            | `http://localhost:8880` |

For production deployments, be sure to read the Security Note below.

## Available Endpoints
For detailed flow diagrams and architecture documentation, see [`docs/architecture.md`](docs/architecture.md).

### OpenID Connect Discovery
```
GET /.well-known/openid-configuration
```

Returns the OpenID Connect provider metadata used by clients for discovery.

### Authorization
```
GET /authorize
```

Implements the authorization code flow for a pre-seeded test user.

### Token Exchange
```
POST /token
```

Exchanges authorization codes for access and refresh tokens, or refreshes existing tokens.

### JSON Web Key Set (JWKS)
```
GET /jwks.json
```

Public JWK used by clients and resource servers to validate tokens.

## User Authentication and Information
Asteroid does not perform user authentication itself.  
The authenticated user is provided by the upstream layer via:

```
X-Authenticated-User: <subject>
```

Asteroid resolves user information on demand through a pluggable provider:

```go
// Development
userinfoProvider := source.NewYAMLProvider("./data/users.yaml")

// Production
userinfoProvider := source.NewHTTPProvider(apiURL, httpClient)
```

The provider acts as the trust boundary:

- If the user no longer exists - token issuance is denied  
- No user data is stored or cached inside Asteroid  
- Any identity backend can be integrated by implementing the interface

This keeps OIDC authorization pure, independent, and decoupled from your authentication system.

## Storage
Asteroid includes an in-memory store by default.  
If you want to use Redis, build with:

```
go build -tags redis -o bin/asteroid ./cmd/server
```

Redis is recommended for production-grade authorization code and token storage.

## Docker
Asteroid is not dockerized by default — it runs as a small, self-contained Go binary.

For developers who use Redis as storage backend, minimal Docker Compose
examples are available under the [examples/](examples/) directory.

The examples contain only the essentials.

## Security Note
Asteroid automatically generates signing keys at startup and handles key rotation transparently. Keys are never stored in version control and are managed entirely through the built-in key management system.

In development environments, generated keys are persisted to local files for convenience. For production deployments, we highly recommend configuring a Key Management Service (KMS) through the persister interface for secure key storage and rotation.

In addition, Asteroid should not be exposed directly to the public internet.  
We recommend placing it behind a reverse proxy:

- **nginx (via unix domain socket)**  
  Provides optimal isolation, no TCP surface, and keeps TLS termination outside the Asteroid process.

- **AWS ALB (directly in front of Asteroid)**  
  A clean, minimal setup where TLS termination and access control are fully handled by ALB, keeping Asteroid isolated from direct exposure and free from transport-layer concerns.

By delegating TLS termination, rate limiting, and access policies to the upstream layer, the Asteroid binary can remain small, simple, and secure—consistent with its UNIX-inspired design philosophy.

Asteroid speaks HTTP internally. In production, clients must access the issuer over HTTPS, with TLS termination
handled entirely by the upstream proxy (nginx, Envoy, ALB, etc.). This keeps Asteroid transport-layer agnostic while remaining compliant with OIDC.

## Recommended Deployment
A well-engineered Linux or BSD system remains one of the most robust and predictable foundations available.

Full control over the kernel, filesystem, resource limits, and networking policies provides a level of transparency that containerized or serverless runtimes cannot match.

A typical production topology is:

```
Internet / Clients
↓
TLS termination (NGINX / ALB / Envoy)
↓
Asteroid (listening on a UNIX domain socket)
↓
Redis (volatile session/cache storage)
```

This model provides:

- clear separation of responsibilities (TLS, HTTP, routing handled by the proxy)
- predictable performance by running Asteroid as a native Linux binary
- minimal moving parts and no container overhead
- a stable environment suitable for EC2, on-premise Linux, or any POSIX system

Docker is included only as an example for local development. For production systems, 
deploying Asteroid directly on Linux (e.g., Amazon EC2)
with a reverse proxy and a UNIX domain socket is the recommended configuration.

## License
Copyright KEI SAWAMURA 2025 (a.k.a keix)  
Asteroid is licensed under the MIT License. Copying and modifying is encouraged and appreciated.
