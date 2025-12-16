# Asteroid
This directory provides a Docker example of Asteroid.

**Note:**  
In production, Asteroid is intended to run behind a reverse proxy and typically listens on a UNIX domain socket rather than a TCP port. 
This example uses plain HTTP on port 8880 only for ease of demonstration.

## Docker Example
The example includes the following components:

- Asteroid (OIDC provider)
- NGINX (reverse proxy)
- Redis (volatile session/cache storage)

These services form a minimal but complete OIDC deployment topology for local development.

## Run the Example
Run the following command from within the examples/ directory:

```
docker compose up --build
```

After startup, the following OIDC endpoints become available:

```
http://localhost:8880/.well-known/openid-configuration
http://localhost:8880/authorize
http://localhost:8880/token
http://localhost:8880/jwks.json
```

If these resolve, Asteroid is running correctly.

## Why do NGINX and Asteroid both use port 8880?
In this example, all components use HTTP on port 8880 so that the OpenID
Connect issuer URL matches the externally reachable endpoint, as required by OIDC.

The example aligns:
- NGINX listens on port 8880
- Asteroid serves its HTTP endpoint on port 8880
- the issuer is configured to use port 8880

This uniform port setup avoids issuer mismatches during local development.
It is only for demonstration purposes; production deployments typically use TLS at the proxy layer (e.g., port 443) while Asteroid runs on a UNIX domain socket.

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
