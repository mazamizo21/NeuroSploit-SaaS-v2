# SSH Service Skill

## Overview
Service-specific methodology for SSH enumeration, algorithm review, and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force or password spraying unless explicit authorization is confirmed.
3. Avoid high-rate connection attempts.

## Methodology

### 1. Banner and Host Key Collection
- Capture SSH banner and host key fingerprints.
- Record supported host key types.

### 2. Algorithm and Auth Method Enumeration
- Enumerate key exchange, ciphers, and MACs.
- Identify enabled authentication methods.

### 3. Safe Access Validation
- Validate provided credentials only.
- Avoid brute force on external targets.

## Deep Dives
Load references when needed:
1. Host key fingerprints: `references/host_keys.md`
2. Algorithm review: `references/algorithms.md`
3. Auth method enumeration: `references/auth_methods.md`

## Evidence Collection
1. `ssh_fingerprint.json` with banner, host keys, and algorithms (parsed from `nmap` output).
2. `evidence.json` with raw script outputs and keyscan evidence.
3. `findings.json` with weak algorithms or risky configs.

## Evidence Consolidation
Use `parse_ssh_nmap.py` to convert Nmap script output into `ssh_fingerprint.json`.

## Success Criteria
- SSH version and key algorithms identified.
- Authentication methods documented.
- Weak or deprecated algorithms flagged with evidence.

## Tool References
- ../toolcards/nmap.md
