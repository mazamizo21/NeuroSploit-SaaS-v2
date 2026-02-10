# Drupal Service Skill

## Overview
Service-first methodology for Drupal enumeration and safe vulnerability validation.

## Scope Rules
1. Only operate on explicitly in-scope sites and domains.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Avoid credential stuffing or login brute force unless explicitly authorized.
4. Use rate limits to avoid overwhelming production sites.

## Methodology

### 1. Fingerprinting and Versioning
- Identify Drupal core version and installed modules.
- Capture public endpoints and headers that confirm Drupal presence.

### 2. Access Validation
- Use provided credentials only.
- Record authentication success or failure once per site.

### 3. Safe Vulnerability Enumeration
- Use passive and read-only checks for known vulnerable modules.
- Confirm exposure through public files or metadata where possible.

### 4. Risky Exposure Checks
- Identify exposed configuration files or backups.
- Flag publicly accessible directories with sensitive content.

## Deep Dives
Load references when needed:
1. Core versioning: `references/core_versioning.md`
2. Module inventory: `references/module_inventory.md`
3. Authentication endpoints: `references/auth_endpoints.md`
4. Exposure checks: `references/exposure_checks.md`
5. Explicit-only actions: `references/explicit_only_actions.md`

## Service-First Workflow (Default)
1. Discovery: `droopescan` for module inventory.
2. Safe validation: `nuclei` or `nikto` for web issues.
3. Authorized enrichment: confirm core/module versions.
4. Explicit-only: credential attacks or exploit execution.

## Evidence Collection
1. `drupal_inventory.json` with core version, modules, and endpoints (parsed from Droopescan output).
2. `evidence.json` with raw droopescan output and validation notes.
3. `findings.json` with vulnerable modules and exposure evidence.

## Evidence Consolidation
Use `parse_droopescan.py` to convert Droopescan output into `drupal_inventory.json`.

## Success Criteria
- Drupal core and module inventory captured safely.
- High-risk exposures documented with evidence.
- Findings scoped to authorized targets.

## Tool References
- ../toolcards/droopescan.md
- ../toolcards/nuclei.md
- ../toolcards/nikto.md
- ../toolcards/nmap.md
