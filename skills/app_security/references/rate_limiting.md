# Rate Limiting and Abuse Controls

## Checks
1. Validate rate limit headers and enforcement behavior.
2. Confirm IP/user-based throttling on auth and sensitive endpoints.
3. Verify abuse detection alerts or lockout behavior where applicable.
4. Check per-tenant or per-API-key limits for shared environments.
5. Validate reset windows and backoff behavior after 429 responses.

## Evidence Capture
1. Rate limit response evidence and thresholds.
2. Header snapshots (`Retry-After`, `X-RateLimit-*`) and window metadata.
3. Notes on enforcement scope (IP, user, tenant, key).
