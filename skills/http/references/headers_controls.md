# Security Headers and Controls

## Goals
1. Capture security headers and caching posture.
2. Identify missing or weak protections.
3. Record header evidence per endpoint.

## Safe Checks
1. `curl -I https://target`
2. `httpx -json` with header capture

## Indicators to Record
1. Missing `Strict-Transport-Security` on HTTPS.
2. Missing `X-Content-Type-Options` or `X-Frame-Options`.
3. Weak `Content-Security-Policy`.
4. Missing `Referrer-Policy` or `Permissions-Policy`.
5. Missing cache protections on sensitive endpoints.

## Evidence Checklist
1. Header list with values by endpoint.
2. Notes on missing or weak headers.
3. Cache-control and cookie security flags evidence.
