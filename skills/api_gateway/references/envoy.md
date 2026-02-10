# Envoy Playbook

## Identification Hints
- Envoy Proxy deployments expose an admin interface that should be restricted.
- If the admin interface is accessible, treat it as high-risk exposure.

## Safe Checks
1. Confirm gateway presence via standard HTTP responses and TLS certs.
2. Record admin interface exposure without modifying configuration.
3. Inventory public routes via OpenAPI specs and developer docs.

## Evidence Capture
- Record gateway type and any exposed admin interfaces.
- Capture safe route inventory and auth scheme summary.

## References
- https://www.envoyproxy.io/docs/envoy/latest/operations/admin
