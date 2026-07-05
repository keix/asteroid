# Asteroid
This document records historical performance measurements from the ES256-only implementation. ID Tokens now use RS256, so token endpoint results must be re-measured before being treated as current.

## Benchmark Overview
This section presents baseline performance measurements for Asteroid's OIDC endpoints, demonstrating microsecond-level latencies achieved through its streamlined architecture.

All benchmarks were conducted on native Gentoo Linux using CPU-optimized Go toolchain, measuring the complete authorization code flow from discovery to token exchange.

## Environment
- **OS:** Gentoo Linux 6.12.21 x86_64
- **CPU:** Intel Core i5-14600K (14th Gen)
- **libc:** glibc 2.41-r5
- **Go:** Go 1.24.6 (locally built, CPU-tuned)

Measured with zero container overhead.

## Benchmark Method
One benchmark "set" performs the full OIDC sequence:

1. `GET /.well-known/openid-configuration`
2. `GET /authorize`
3. `POST /token`
4. `GET /jwks.json`

## Endpoint Latency (Application Layer)
These values reflect Asteroid's actual execution time inside Gin, measured directly from server logs (µs precision).

| Endpoint | Typical Latency |
|----------|-----------------|
| `/.well-known/openid-configuration` | **10–25 µs** |
| `/authorize` | **120–180 µs** |
| `/token` (historical ES256 measurement) | **300–450 µs** |
| `/jwks.json` | **10–25 µs** |

A full round-trip completes in 400–700 µs end-to-end.

## Performance Improvements
The latest architecture delivers **significant performance gains**:

- **Cryptographic Algorithm:**
  - **RSA256:** 1500–2000 µs per JWT signing operation
  - **ES256:** 300–450 µs per JWT signing operation (~5x faster)
- **Key rotation:** Automatic key management with zero measurable overhead
- **Memory efficiency:** All operations now in sub-millisecond range

Asteroid's performance comes from its modernized architecture:
- OIDC logic runs **directly above the HTTP layer**
- No heavy framework overhead
- **Automatic key generation and rotation**
- All validation and token generation happen in memory
- **ECDSA cryptography** delivers superior speed

## Summary
Asteroid delivers consistently low-latency OIDC responses on commodity hardware. The small, memory-resident design makes performance predictable and stable even under sustained load.

JWT access tokens retain ECDSA-based signing. ID Tokens now use mandatory-to-implement RS256; their latency should be re-benchmarked separately.
