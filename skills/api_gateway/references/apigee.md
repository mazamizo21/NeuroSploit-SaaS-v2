# Apigee Playbook

## Identification Hints
- Apigee is an API management platform; environments often expose API proxies and developer portals.
- Look for public API docs or developer portals for route inventory.

## Safe Checks
1. Inventory API proxies and published docs without changing configuration.
2. Validate auth schemes and CORS settings on public endpoints.
3. Record rate-limit headers and policy hints if present.

## Evidence Capture
- Record proxy base paths, auth requirements, and documentation endpoints.
- Capture any public misconfiguration evidence (open endpoints, permissive CORS).

## References
- https://cloud.google.com/apigee/docs/api-platform/get-started/what-apigee
- https://cloud.google.com/apigee/docs/api-platform/publish/what-api-proxy
