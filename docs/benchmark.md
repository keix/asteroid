# Asteroid Benchmark
This page summarizes the baseline performance of Asteroid — measured on a modern Gentoo Linux environment with a CPU-tuned Go toolchain.

## Environment
- **OS:** Gentoo Linux 6.12.21 x86_64
- **CPU:** Intel Core i5-14600K (14th Gen)
- **libc:** glibc 2.41-r5
- **Go:** Go 1.24.6 (locally built, CPU-tuned)

All benchmarks were executed on bare metal with no container overhead.

## Benchmark Method
One benchmark “set” performs the full OIDC sequence:

1. `GET /.well-known/openid-configuration`
2. `GET /authorize`
3. `POST /token`
4. `GET /jwks.json`

## Endpoint Latency (Application Layer)
These values reflect Asteroid's actual execution time inside Gin, measured directly from server logs (µs precision).

| Endpoint | Typical Latency |
|----------|-----------------|
| `/.well-known/openid-configuration` | **20–30 µs** |
| `/authorize` | **120–200 µs** |
| `/token` (RSA256 signing) | **1.5–2.0 ms** |
| `/jwks.json` | **20–30 µs** |

Asteroid’s performance comes from its architecture:
- OIDC logic runs **directly above the HTTP layer**
- No heavy framework overhead
- RSA private key loaded once at startup
- All validation and token generation happen in memory

## Summary
Asteroid delivers consistently low-latency OIDC responses on commodity hardware. The small, memory-resident design makes performance predictable and stable even under sustained load.

## Appendix (Environment Notes)
Benchmarks were measured on a native Gentoo Linux 6.12.21 system (glibc 2.41-r5) using an optimized Go 1.24.6 toolchain.
Environment details are included for reproducibility, as libc and compiler versions can influence low-latency workloads.