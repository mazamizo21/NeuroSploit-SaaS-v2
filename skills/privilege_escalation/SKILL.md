# Privilege Escalation Skill

## Overview
Validate privilege escalation paths safely and capture evidence with minimal disruption.

## Scope Rules
1. Only operate on explicitly authorized hosts and accounts.
2. External targets: exploitation requires explicit authorization (external_exploit=explicit_only).
3. Prefer misconfiguration evidence over active exploitation.
4. Avoid persistence unless explicitly authorized.

## Methodology

### 1. Baseline Enumeration
- Collect system, service, and permission context.
- Identify misconfigurations without exploitation.

### 2. Platform-Specific Review
- Linux: SUID/SGID, cron, permissions, PATH issues.
- Windows: service paths, weak permissions, token privileges.

### 3. Explicit-Only Exploitation
- Use exploits only when authorized.
- Capture minimal proof of elevation and stop.

## Deep Dives
Load references when needed:
1. Baseline enumeration: `references/baseline_enumeration.md`
2. Linux vectors: `references/linux_vectors.md`
3. Windows vectors: `references/windows_vectors.md`
4. Explicit-only exploitation: `references/explicit_only_exploitation.md`
5. Proof of access: `references/proof_of_access.md`

## Evidence Collection
1. `privesc_summary.json` with enumeration highlights (from PEAS output).
2. `evidence.json` with misconfiguration proof and redactions.
3. `findings.json` with risk impact notes.

## Evidence Consolidation
Use `summarize_peas.py` to convert PEAS output into `privesc_summary.json`.

## Success Criteria
- Escalation paths identified with evidence.
- Minimal proof captured when authorized.
- No unauthorized changes performed.
