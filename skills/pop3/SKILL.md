# POP3 Service Skill

## Overview
Service-specific methodology for POP3 enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force or password spraying unless explicit authorization is confirmed.
3. Avoid mailbox content access unless explicitly authorized.
4. Exploit workflows require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Service Fingerprinting
- Identify version, banners, and STLS support.

### 2. Capability Discovery
- Capture supported auth methods and extensions.

### 3. Safe Access Validation
- Use provided credentials only.

### 4. Explicit-Only Actions
- Mailbox listing or message retrieval only when authorized.

## Service-First Workflow (Default)
1. Discovery: banner and capabilities via `nmap` or `netcat`.
2. Access validation: provided credentials only.
3. Explicit-only: online auth testing only when authorization is confirmed.

## Deep Dives
Load references when needed:
1. POP3 capabilities: `references/capabilities.md`
2. TLS posture: `references/tls_posture.md`
3. Authentication methods: `references/auth_methods.md`

## Evidence Collection
1. `pop3_info.json` with banner, capabilities, and auth evidence (parsed from `nmap` output).
2. `evidence.json` with raw POP3 command output and TLS negotiation evidence.
3. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `parse_pop3_nmap.py` to convert Nmap script output into `pop3_info.json`.

## Success Criteria
- POP3 service identified and characterized.
- Access controls validated safely.
- Risky settings documented with evidence.

## Tool References
- ../toolcards/nmap.md
- ../toolcards/netcat.md
- ../toolcards/socat.md
- ../toolcards/hydra.md
