# Redis Service Skill

## Overview
Service-specific methodology for Redis enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force unless explicit authorization is confirmed.
3. Avoid destructive commands such as CONFIG SET, FLUSHALL, or SAVE unless authorized.

## Methodology

### 1. Version and Access Checks
- Validate service availability and auth requirements.
- Capture INFO output for version and configuration context.

### 2. Safe Data Validation
- Use read-only commands when possible.
- Sample minimal data required for evidence.

### 3. Authorization Guardrails
- Only attempt AUTH with provided credentials.
- Avoid persistence or replication changes unless explicitly authorized.

## Deep Dives
Load references when needed:
1. Authentication posture: `references/auth_posture.md`
2. Persistence and replication: `references/persistence.md`
3. Configuration hardening: `references/config_hardening.md`

## Evidence Collection
1. `redis_info.json` with version and config highlights (summarized from INFO output).
2. `evidence.json` with raw INFO output and config snapshots.
3. `findings.json` with weak auth or risky configs.

## Evidence Consolidation
Use `summarize_redis_info.py` to convert INFO output into `redis_info.json`.

## Success Criteria
- Redis service identified and authenticated safely.
- Auth configuration and access scope documented.
- Risky configurations documented with evidence.

## Tool References
- ../toolcards/redis-cli.md
- ../toolcards/nmap.md
