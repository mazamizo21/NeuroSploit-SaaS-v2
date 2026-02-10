# RDP Service Skill

## Overview
Service-specific methodology for RDP enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force or password spraying unless explicit authorization is confirmed.
3. Avoid repeated connection attempts.
4. Interactive sessions or drive/device redirection require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Security and Encryption Discovery
- Identify RDP security modes and encryption settings.
- Capture NTLM info when available.

### 2. Safe Access Validation
- Use provided credentials only.
- Prefer `/auth-only` checks to avoid full sessions.

## Service-First Workflow (Default)
1. Discovery: RDP security modes, encryption settings, and NTLM info via `nmap`.
2. Access validation: `xfreerdp /auth-only` with provided credentials only.
3. Explicit-only sessions: full interactive sessions only when authorization is confirmed.

## Deep Dives
Load references when needed:
1. Security modes and encryption: `references/security_modes.md`
2. NTLM info fields: `references/ntlm_info.md`
3. Explicit-only session controls: `references/session_controls.md`

## Evidence Collection
1. `rdp_info.json` with security mode and NTLM metadata (parsed from `nmap` output).
2. `evidence.json` with raw `nmap` script output and auth-only validation notes.
3. `findings.json` with risky settings or weak configurations.

## Evidence Consolidation
Use `parse_rdp_nmap.py` to convert Nmap script output into `rdp_info.json`.

## Success Criteria
- RDP security settings documented.
- Access validation completed safely.
- Risky settings documented with evidence.

## Tool References
- ../toolcards/xfreerdp.md
- ../toolcards/nmap.md
