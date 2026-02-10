# FTP Service Skill

## Overview
Service-specific methodology for FTP enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force or password spraying unless explicit authorization is confirmed.
3. Avoid file writes or uploads unless explicitly authorized.
4. Exploit workflows require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Service Fingerprinting
- Identify version, banners, and TLS/FTPS support.

### 2. Safe Access Validation
- Test anonymous access where permitted.
- Use provided credentials only.

### 3. Read-Only Enumeration (Authorized)
- List directories and permissions without modifying files.

### 4. Explicit-Only Actions
- Any uploads, deletes, or exploitation only when authorized.

## Deep Dives
Load references when needed:
1. Banner and FTPS support: `references/banner_tls.md`
2. Anonymous access: `references/anonymous_access.md`
3. Permissions review: `references/permissions.md`

## Service-First Workflow (Default)
1. Discovery: banner and version via `nmap` scripts.
2. Access validation: banner checks with `netcat` or `socat`.
3. Authorized auth checks: provided credentials only.
4. Explicit-only: online password testing or write actions only when authorization is confirmed.

## Evidence Collection
1. `ftp_info.json` with banner, version, and auth mode evidence (parsed from `nmap` output).
2. `evidence.json` with raw banner output and anonymous listing evidence.
3. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `parse_ftp_nmap.py` to convert Nmap script output into `ftp_info.json`.

## Success Criteria
- FTP service identified and characterized.
- Access controls validated safely.
- Risky settings documented with evidence.

## Tool References
- ../toolcards/nmap.md
- ../toolcards/netcat.md
- ../toolcards/socat.md
- ../toolcards/hydra.md
