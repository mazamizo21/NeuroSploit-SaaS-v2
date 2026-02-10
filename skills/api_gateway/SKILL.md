# API Gateway Service Skill

## Overview
Service-first methodology for API gateway discovery, route inventory, and safe validation.

## Scope Rules
1. Only operate on explicitly in-scope gateways and API hosts.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Avoid auth bypass tests, injection, or rate-limit evasion unless explicitly authorized.
4. Respect rate limits and throttle requests for production endpoints.

## Methodology

### 1. Fingerprinting and Provider Identification
- Identify gateway type via headers, TLS certs, and error responses.
- Record upstream API base paths and known gateway endpoints.

### 2. Route and Schema Discovery (Authorized)
- Look for OpenAPI/Swagger specs (`/openapi.json`, `/swagger.json`, `/api-docs`).
- Crawl documentation and developer portals for route inventory.
- Use scoped route discovery to build a minimal map of endpoints.

### 3. Auth and Policy Validation
- Identify auth schemes (API keys, OAuth, JWT, mTLS).
- Flag missing auth on sensitive endpoints and overly permissive CORS.

### 4. Safe Validation
- Use read-only requests to confirm exposure.
- Avoid fuzzing or bypass attempts without explicit authorization.

## Deep Dives
Load references when needed:
1. Kong gateway routes and plugins: `references/kong.md`
2. Apigee proxy and policy review: `references/apigee.md`
3. NGINX gateway routing and auth: `references/nginx.md`
4. Envoy listeners and filters: `references/envoy.md`

## Service-First Workflow (Default)
1. Discovery: `httpx` + `sslscan` + `nmap` for gateway identification.
2. Route inventory: `katana` crawl and OpenAPI spec discovery.
3. Safe validation: `kiterunner` with low concurrency for route discovery.
4. Explicit-only: auth bypass or injection testing.

## Evidence Collection
1. `api_gateway_inventory.json` with gateway type, auth scheme, and routes (summarized from discovery outputs).
2. `evidence.json` with raw discovery outputs and headers.
3. `findings.json` with misconfiguration evidence.

## Evidence Consolidation
Use `summarize_gateway_inventory.py` to convert discovery outputs into `api_gateway_inventory.json`.

## Success Criteria
- Gateway type identified.
- Route inventory captured safely.
- Misconfigurations documented with evidence.

## Tool References
- ../toolcards/httpx.md
- ../toolcards/sslscan.md
- ../toolcards/nmap.md
- ../toolcards/katana.md
- ../toolcards/kiterunner.md
- ../toolcards/nuclei.md
