# MSSQL Service Skill

## Overview
Service-specific methodology for Microsoft SQL Server enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force unless explicit authorization is confirmed.
3. Use read-only queries and avoid configuration changes.
4. Exploit workflows require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Version and Instance Discovery
- Use service scripts to identify SQL Server version and instance info.
- Capture authentication mode signals when available.

### 2. Safe Access Validation
- Use provided credentials only.
- Validate access with minimal queries such as `SELECT @@VERSION` and `SELECT name FROM sys.databases`.

### 3. Risk Review (Authorized)
- Review server configuration exposure with read-only queries.
- Avoid enabling features like xp_cmdshell.

## Service-First Workflow (Default)
1. Discovery: identify SQL Server version and instance info via `nmap`.
2. Access validation: read-only queries via `sqlcmd` or `tsql` with provided credentials.
3. Safe configuration review: read-only checks for risky settings and exposures.
4. Explicit-only exploit workflows: advanced injection or exploitation tools only when authorization is confirmed.

## Deep Dives
Load references when needed:
1. Authentication mode validation: `references/authentication.md`
2. Metadata inventory: `references/metadata_checks.md`
3. Read-only configuration review: `references/config_review.md`

## Evidence Collection
1. `db_access.json` with version, databases, and login context (prefer JSON output for parsing).
2. `evidence.json` with raw query outputs and connection metadata.
3. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `parse_sqlcmd_json.py` to convert `sqlcmd` JSON output into `db_access.json`.

## Success Criteria
- SQL Server version identified.
- Access validation completed safely.
- Risky settings documented with evidence.

## Tool References
- ../toolcards/tsql.md
- ../toolcards/sqlcmd.md
- ../toolcards/sqlninja.md
- ../toolcards/metasploit-framework.md
- ../toolcards/nmap.md
