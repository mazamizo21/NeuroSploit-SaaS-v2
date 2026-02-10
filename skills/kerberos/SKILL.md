# Kerberos Service Skill

## Overview
Service-specific methodology for Kerberos authentication validation and ticket hygiene checks.

## Scope Rules
1. Only operate on explicitly in-scope realms and KDC hosts.
2. External targets: no user enumeration or ticket attacks unless explicit authorization is confirmed.
3. Use provided credentials or keytabs only.
4. Exploit or abuse workflows require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Realm and KDC Context
- Confirm realm details and KDC reachability.
- Record clock skew errors and configuration issues.

### 2. Ticket Acquisition (Authorized)
- Use `kinit` to obtain a TGT with provided credentials.
- Use `klist` to verify ticket cache, lifetimes, and renewability.

### 3. Safe Validation
- Document authentication failures and pre-auth requirements.
- Avoid Kerberoasting or AS-REP roasting unless explicitly authorized.

## Service-First Workflow (Default)
1. Realm and KDC validation: reachability and clock skew via `nmap` and safe checks.
2. Ticket acquisition: `kinit` with provided credentials or keytabs.
3. Ticket inspection: `klist` for cache presence, lifetime, and renewability.
4. Explicit-only deep checks: user enumeration or ticket abuse only when authorization is confirmed.

## Deep Dives
Load references when needed:
1. Realm validation and KDC discovery: `references/realm_validation.md`
2. Ticket hygiene checks: `references/ticket_hygiene.md`
3. Explicit-only abuse checks: `references/explicit_only_abuse.md`

## Evidence Collection
1. `kerberos_tickets.json` with ticket metadata (parsed from `klist`).
2. `evidence.json` with raw `klist` output and auth notes.
3. `findings.json` with auth or policy risks.

## Evidence Consolidation
Use `parse_klist.py` to convert `klist` output into `kerberos_tickets.json`.

## Success Criteria
- Realm and KDC reachability verified.
- Ticket cache validated with provided credentials.
- Risky authentication policies documented.

## Tool References
- ../toolcards/kinit.md
- ../toolcards/klist.md
- ../toolcards/kerbrute.md
- ../toolcards/nmap.md
