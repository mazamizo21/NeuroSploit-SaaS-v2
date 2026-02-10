# MySQL Service Skill

## Overview
Service-specific methodology for MySQL/MariaDB enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force unless explicit authorization is confirmed.
3. Use read-only queries where possible and avoid destructive actions.

## Methodology

### 1. Version and Service Validation
- Capture version and handshake metadata.
- Identify TLS requirements or auth plugins.

### 2. Access Validation
- Use provided credentials only.
- Confirm least-privilege access by listing databases and grants.

### 3. Safe Data Validation
- Sample minimal data required for evidence.
- Avoid bulk exports unless explicitly authorized.

## Deep Dives
Load references when needed:
1. Authentication and TLS posture: `references/authentication.md`
2. Privilege review: `references/privileges.md`
3. Secure configuration checks: `references/secure_config.md`

## Evidence Collection
1. `db_access.json` with version, auth mode, and privileges (parsed from `SHOW` output).
2. `evidence.json` with raw `SHOW` outputs and connection metadata.
3. `findings.json` with weak auth or risky permissions.

## Evidence Consolidation
Use `parse_mysql_show.py` to convert MySQL `SHOW` outputs into `db_access.json`.

## Success Criteria
- MySQL service identified and authenticated safely.
- Database visibility and grants documented.
- Risky permissions documented with evidence.

## Tool References
- ../toolcards/mysql.md
- ../toolcards/nmap.md
