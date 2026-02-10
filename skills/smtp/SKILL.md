# SMTP Service Skill

## Overview
Service-specific methodology for SMTP enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no user enumeration or password spraying unless explicit authorization is confirmed.
3. Avoid sending test emails or relays unless explicitly authorized.
4. Exploit workflows require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Service Fingerprinting
- Identify version, banners, and STARTTLS support.

### 2. Capability Discovery
- Use EHLO to capture supported extensions and auth methods.

### 3. Safe Access Validation
- Use provided credentials only.

### 4. Explicit-Only Checks
- User enumeration or relay testing only when authorized.

## Service-First Workflow (Default)
1. Discovery: banner and capabilities via `nmap` or `netcat`.
2. Access validation: use provided credentials only.
3. Explicit-only: `smtp-user-enum` or online auth testing only when authorization is confirmed.

## Deep Dives
Load references when needed:
1. SMTP capabilities: `references/capabilities.md`
2. TLS posture: `references/tls_posture.md`
3. Authentication methods: `references/auth_methods.md`

## Evidence Collection
1. `smtp_info.json` with banner, capabilities, and auth evidence (parsed from `nmap` output).
2. `evidence.json` with raw SMTP command output and TLS negotiation evidence.
3. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `parse_smtp_nmap.py` to convert Nmap script output into `smtp_info.json`.

## Success Criteria
- SMTP service identified and characterized.
- Access controls validated safely.
- Risky settings documented with evidence.

## Tool References
- ../toolcards/nmap.md
- ../toolcards/netcat.md
- ../toolcards/socat.md
- ../toolcards/smtp-user-enum.md
- ../toolcards/hydra.md
