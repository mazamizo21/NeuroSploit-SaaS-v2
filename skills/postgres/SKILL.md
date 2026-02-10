# PostgreSQL Service Skill

## Overview
Service-specific methodology for PostgreSQL enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force unless explicit authorization is confirmed.
3. Use read-only queries where possible and avoid destructive actions.

## Methodology

### 1. Version and Service Validation
- Capture version metadata and connection requirements.
- Identify TLS requirements and authentication methods.

### 2. Access Validation
- Use provided credentials only.
- Confirm least-privilege access by listing databases, schemas, and roles.

### 3. Safe Data Validation
- Sample minimal data required for evidence.
- Avoid bulk exports unless explicitly authorized.

## Deep Dives
Load references when needed:
1. Authentication and TLS posture: `references/authentication.md`
2. Roles and privileges: `references/roles_privileges.md`
3. Security settings: `references/security_settings.md`

## Evidence Collection
1. `db_access.json` with version, roles, and privileges (parsed from `psql` output).
2. `evidence.json` with raw `psql` outputs and connection metadata.
3. `findings.json` with weak auth or risky permissions.

## Evidence Consolidation
Use `parse_psql_table.py` to convert `psql` table outputs into `db_access.json`.

## Success Criteria
- PostgreSQL service identified and authenticated safely.
- Database visibility and role privileges documented.
- Risky permissions documented with evidence.

## Tool References
- ../toolcards/psql.md
- ../toolcards/nmap.md
