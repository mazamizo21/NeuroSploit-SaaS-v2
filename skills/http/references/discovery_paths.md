# Content and Endpoint Discovery

## Goals
1. Identify exposed directories, files, and API paths.
2. Use conservative rates to avoid disruption.
3. Record discovered paths with status and response size.

## Safe Checks
1. `ffuf` or `gobuster` with low rate and status filtering.
2. Check `robots.txt`, `sitemap.xml`, and `/.well-known/`.
3. Limit wordlists to common paths on external targets.

## Indicators to Record
1. Administrative endpoints exposed.
2. Sensitive files or backups.
3. Hidden API routes or undocumented endpoints.

## Evidence Checklist
1. Endpoint list with status codes and sizes.
2. Notes on sensitive paths and access controls.
3. Evidence of redirects or access denials (401/403).
