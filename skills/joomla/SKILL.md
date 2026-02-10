# Joomla Service Skill

## Overview
Service-first methodology for Joomla enumeration and safe vulnerability validation.

## Scope Rules
1. Only operate on explicitly in-scope sites and domains.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Avoid credential stuffing or login brute force unless explicitly authorized.
4. Use rate limits to avoid overwhelming production sites.

## Methodology

### 1. Fingerprinting and Versioning
- Identify Joomla core version and installed components.
- Capture public endpoints and headers that confirm Joomla presence.

### 2. Access Validation
- Use provided credentials only.
- Record authentication success or failure once per site.

### 3. Safe Vulnerability Enumeration
- Use passive and read-only checks for known vulnerable components.
- Confirm exposure through public manifests or metadata where possible.

### 4. Risky Exposure Checks
- Identify exposed backups, logs, or installer remnants.
- Flag directory listing on component folders.

## Deep Dives
Load references when needed:
1. Core versioning: `references/core_versioning.md`
2. Component inventory: `references/component_inventory.md`
3. Authentication endpoints: `references/auth_endpoints.md`
4. Exposure checks: `references/exposure_checks.md`
5. Explicit-only actions: `references/explicit_only_actions.md`

## Service-First Workflow (Default)
1. Discovery: `joomscan` for component inventory.
2. Safe validation: `nuclei` or `nikto` for web issues.
3. Authorized enrichment: confirm core/component versions.
4. Explicit-only: credential attacks or exploit execution.

## Evidence Collection
1. `joomla_inventory.json` with core version, components, and endpoints (parsed from Joomscan output).
2. `evidence.json` with raw joomscan output and validation notes.
3. `findings.json` with vulnerable components and exposure evidence.

## Evidence Consolidation
Use `parse_joomscan.py` to convert Joomscan output into `joomla_inventory.json`.

## Success Criteria
- Joomla core and component inventory captured safely.
- High-risk exposures documented with evidence.
- Findings scoped to authorized targets.

## Tool References
- ../toolcards/joomscan.md
- ../toolcards/nuclei.md
- ../toolcards/nikto.md
- ../toolcards/nmap.md
