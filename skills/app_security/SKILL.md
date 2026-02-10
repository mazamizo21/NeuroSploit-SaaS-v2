# Application Security Patterns Skill

## Overview
Service-first methodology for application security validation focused on common patterns: authentication, session handling, access control, input validation, and data protection.

## Scope Rules
1. Only operate on explicitly in-scope applications and environments.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Avoid destructive tests and rate-limit all active checks.
4. Use provided credentials only; no brute force unless explicitly authorized.

## Methodology

### 1. Application Mapping
- Identify entry points, auth flows, and API endpoints.
- Capture documented routes and OpenAPI/Swagger specs.

### 2. Authentication and Session Handling
- Validate login protections, session lifetime, and cookie security flags.
- Identify missing MFA enforcement or weak session invalidation.

### 3. Access Control
- Validate role-based access control and object-level authorization.
- Check for IDOR patterns using read-only requests.

### 4. Input Validation and Injection Safety
- Identify unsanitized input points and missing validation.
- Use safe, non-destructive payloads for validation only.

### 5. Sensitive Data Exposure
- Check for exposed secrets in responses, logs, or client-side code.
- Validate transport security and caching headers.

### 6. Explicit-Only Actions
- Exploit attempts, destructive testing, or credential attacks require explicit authorization.

## Deep Dives
Load references based on the validation focus:
1. Authentication: `references/authentication.md`
2. Session handling: `references/session_handling.md`
3. Access control: `references/access_control.md`
4. Input validation: `references/input_validation.md`
5. Sensitive data exposure: `references/data_exposure.md`
6. API auth and scopes: `references/api_auth.md`
7. Rate limiting: `references/rate_limiting.md`
8. Security headers: `references/security_headers.md`

## Service-First Workflow (Default)
1. Discovery: `httpx`, `katana`, and OpenAPI spec checks.
2. Safe validation: `nuclei` and `burpsuite` for non-destructive checks.
3. Targeted checks: `arjun` for parameter discovery and `ffuf` with conservative rates.
4. Explicit-only: `sqlmap`, `dalfox`, or active exploit validation.

## Evidence Collection
1. `app_inventory.json` with endpoints, auth flows, and security headers.
2. `app_security_findings.json` with validated issues and evidence.
3. `evidence.json` with raw headers, rate limit evidence, and IDOR validation notes.
4. `findings.json` normalized for reporting (use `nuclei_to_findings` or `summarize_findings` outputs).

## Evidence Consolidation
1. Use `headers_to_json.py` to capture security headers into `app_inventory.json`.
2. Use `rate_limit_report.py` to summarize rate limit behavior.
3. Use `idors_to_json.py` for object access validation evidence.
4. Use `merge_findings.py` and `summarize_findings.py` to normalize `findings.json`.
5. Use `package_evidence.py` to bundle raw HTTP evidence into `evidence.json`.

## Success Criteria
- App surface mapped safely.
- Auth/session/access control posture documented.
- Findings captured with evidence.

## Tool References
- ../toolcards/httpx.md
- ../toolcards/katana.md
- ../toolcards/nuclei.md
- ../toolcards/burpsuite.md
- ../toolcards/arjun.md
- ../toolcards/ffuf.md
- ../toolcards/sqlmap.md
- ../toolcards/dalfox.md
