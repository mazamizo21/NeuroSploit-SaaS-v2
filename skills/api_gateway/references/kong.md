# Kong Gateway Playbook

## Identification Hints
- Kong Gateway uses a separate Admin API; default ports are commonly 8001 (HTTP) and 8444 (HTTPS).
- Treat any exposed Admin API as a high-risk misconfiguration.

## Safe Checks
1. Confirm gateway presence via standard HTTP responses and TLS certs.
2. If Admin API is reachable, record exposure but avoid modifying or configuring routes.
3. Inventory public routes via OpenAPI specs and gateway docs only.

## Evidence Capture
- Record gateway type and any exposed Admin API endpoints.
- Capture safe route inventory and auth scheme summary.

## References
- https://docs.konghq.com/gateway/latest/admin-api/
- https://docs.konghq.com/gateway/latest/
