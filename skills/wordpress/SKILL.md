# WordPress Service Skill

## Overview
Service-first methodology for WordPress enumeration and safe vulnerability validation.

## Scope Rules
1. Only operate on explicitly in-scope sites and domains.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Avoid credential stuffing or login brute force unless explicitly authorized.
4. Use rate limits to avoid overwhelming production sites.

## Methodology

### 1. Fingerprinting and Versioning
- Identify WordPress core version, theme, and exposed plugins.
- Capture public endpoints: `/wp-login.php`, `/wp-json/`, `/xmlrpc.php`.

### 2. Access Validation
- Use provided credentials only.
- Record authentication success or failure once per site.

### 3. Safe Vulnerability Enumeration
- Use passive and read-only checks for known vulnerable plugins/themes.
- Confirm exposure through headers, readme files, or JSON endpoints.

### 4. Risky Exposure Checks
- Identify exposed admin endpoints or misconfigured file listings.
- Flag publicly accessible backups or config artifacts.

## Deep Dives
Load references when needed:
1. Core versioning: `references/core_versioning.md`
2. Plugin and theme inventory: `references/plugin_theme_inventory.md`
3. Authentication endpoints: `references/auth_endpoints.md`
4. Exposure checks: `references/exposure_checks.md`
5. Explicit-only actions: `references/explicit_only_actions.md`

## Service-First Workflow (Default)
1. Discovery: `wpscan` for core/theme/plugin inventory (read-only).
2. Safe validation: `nuclei` or `nikto` for known web issues.
3. Authorized enrichment: confirm versions and exposed endpoints.
4. Explicit-only: credential attacks or exploit execution.

## Evidence Collection
1. `wordpress_inventory.json` with core version, theme, plugins (parsed from WPScan JSON).
2. `evidence.json` with raw wpscan output and validation notes.
3. `findings.json` with vulnerable components and exposure evidence.

## Evidence Consolidation
Use `parse_wpscan_json.py` to convert WPScan JSON into `wordpress_inventory.json`.

## Success Criteria
- WordPress core and plugin inventory captured safely.
- High-risk exposures documented with evidence.
- Findings scoped to authorized targets.

## Tool References
- ../toolcards/wpscan.md
- ../toolcards/nuclei.md
- ../toolcards/nikto.md
- ../toolcards/nmap.md
