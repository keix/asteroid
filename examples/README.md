# Asteroid
This example shows how to run Asteroid in a real-world deployment topology using Docker.

**Note:**  
In production, Asteroid is intended to run behind a reverse proxy and typically listens on a UNIX domain socket rather than a TCP port. 
This example uses plain HTTP on port 8880 only for ease of demonstration.

## Docker Example
This directory provides a runnable example of the Asteroid OIDC provider using:

- Asteroid on port 8880
- NGINX as a reverse proxy (also on 8880)
- Redis as volatile session/cache storage

The example environment demonstrates how a complete OIDC deployment is structured.

## Run the Example
Run the following command from within the examples/ directory:

```
docker compose up --build
```

When all services start, the OIDC endpoints become available at:

```
http://localhost:8880/.well-known/openid-configuration
http://localhost:8880/authorize
http://localhost:8880/token
http://localhost:8880/jwks.json
```

If these resolve, Asteroid is running correctly.

## Why do NGINX and Asteroid both use port 8880?
To keep the issuer consistent. OpenID Connect requires that the issuer URL matches the externally reachable endpoint.

The example aligns:

- the NGINX listen port  
- the Asteroid backend port  
- the configured issuer

All to 8880, ensuring clients resolve correct URLs.

## Redis Warning About vm.overcommit_memory
You may see:

```
WARNING Memory overcommit must be enabled!
```

This is normal on Linux hosts (vm.overcommit_memory=0). Asteroid does not require persistence, so the warning is harmless and can be ignored.

If you want to silence it:

```
sudo sysctl vm.overcommit_memory=1
```

Asteroid does not modify host settings;
operators may choose to adjust kernel parameters.

## Recommended Deployment
A well-engineered Linux or BSD system remains one of the most robust and predictable foundations available.

Full control over the kernel, filesystem,
resource limits, and networking policies provides a level of transparency that containerized or serverless runtimes cannot match.

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

