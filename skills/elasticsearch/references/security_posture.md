# Elasticsearch Security Posture

## Goals
- Identify authentication requirements and exposure risk.
- Confirm transport-level security on HTTP endpoints.

## Safe Checks
- `/_security/_authenticate` (if auth is configured)
- Check HTTP response for authentication challenges
- Verify TLS on HTTPS endpoints

## Indicators
- Open cluster with no auth
- Exposed `_cat` endpoints without auth
- TLS disabled on public interfaces

## Evidence Checklist
- Auth challenge or success details
- TLS state and cipher (if available)
- Exposure of sensitive endpoints

