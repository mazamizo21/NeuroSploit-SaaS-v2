# Security Headers and Transport Controls

## Checks
1. Validate HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.
2. Confirm secure cookie flags and no-cache directives on sensitive endpoints.
3. Validate Referrer-Policy and Permissions-Policy where applicable.
4. Confirm COOP/COEP headers for high-risk apps if supported.
5. Ensure CSP is not overly permissive (no `unsafe-inline` on sensitive pages).

## Evidence Capture
1. Header snapshots and endpoint references.
2. CSP summaries and notable missing headers.
