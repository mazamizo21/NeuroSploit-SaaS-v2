# Lateral Movement Skill

## Overview
Validate lateral movement paths within explicit scope and capture minimal evidence.

## Scope Rules
1. Only move to explicitly in-scope hosts (or approved scope expansion).
2. External targets: lateral movement actions require explicit authorization (external_exploit=explicit_only).
3. Use a single authentication attempt per host unless explicitly authorized.
4. Avoid persistence or long-lived pivots without approval.

## Methodology

### 1. Network Mapping
- Use existing recon outputs to identify reachable hosts.
- Avoid noisy scans or brute force.

### 2. Credential Validation
- Test discovered credentials once per host.
- Record success/failure without repeated attempts.

### 3. Pivoting (Authorized)
- Use short-lived tunnels to validate access.
- Document endpoints and duration.
- Tag MITRE: T1021 (Remote Services), T1078 (Valid Accounts), T1090 (Proxy).

### 4. Explicit-Only Actions
- Remote execution, AD movement, or token reuse require explicit authorization.

## Deep Dives
Load references when needed:
1. Network mapping: `references/network_mapping.md`
2. Credential validation: `references/credential_validation.md`
3. Pivoting and tunnels: `references/pivoting_tunnels.md`
4. AD movement (explicit-only): `references/ad_movement.md`
5. Logging and evidence: `references/logging_evidence.md`

## Evidence Collection
1. `lateral.json` with host and access summaries (parsed from movement logs).
2. `evidence.json` with method and proof of access.
3. `findings.json` with impact notes.
4. `handoff.json` with interactive commands for GUI shell handoff (SSH/WinRM/RDP/etc).

## Evidence Consolidation
Use `summarize_movement_log.py` to convert movement logs into `lateral.json`.

## Success Criteria
- Movement paths validated within scope.
- Evidence captured with minimal impact.
- No unauthorized persistence or changes.
