# Windows Host Validation Skill

## Overview
Service-first methodology for Windows host security validation with safe, read-only checks by default.

## Scope Rules
1. Only operate on explicitly authorized Windows hosts.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Do not change system settings, create accounts, or modify policies without authorization.
4. Treat host output as sensitive; collect only evidence required for remediation.

## Methodology

### 1. System Profile and Patch Level
- Capture OS version, build, and patch level.
- Record domain membership and host role.

### 2. Identity and Privilege Context
- Record current user, group membership, and token privileges.
- Identify local admin membership and delegated rights.

### 3. Security Controls and Hardening
- Check Defender/EDR status, firewall profile, and BitLocker state.
- Validate credential protection features (Credential Guard, LSA protections).

### 4. Misconfiguration and Exposure Checks
- Identify weak service permissions, unquoted service paths, and risky startup entries.
- Review scheduled tasks and autoruns for unexpected entries.

### 5. Explicit-Only Actions
- Credential dumping, exploit attempts, or persistence actions require explicit authorization.

## Deep Dives
Load references when needed:
1. Defense evasion validation: `references/defense_evasion.md`
2. Persistence exposure validation: `references/persistence.md`
3. Hardening checklist: `references/hardening_checklist.md`
4. Credential protection: `references/credential_protection.md`
5. Logging and audit: `references/logging_audit.md`

## Service-First Workflow (Default)
1. Inventory: `systeminfo`, `whoami /all`, and `powershell` system queries.
2. Read-only posture checks: `seatbelt` and `winpeas` scoped runs.
3. Optional patch correlation: `wesng` for advisory mapping.
4. Explicit-only: credential access or exploit validation.

## Evidence Collection
1. `windows_host_inventory.json` with OS, build, and identity summary.
2. `windows_security_posture.json` with controls and hardening checks.
3. `evidence.json` with raw posture outputs and command logs.
4. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `merge_posture.py` to consolidate inventory, defender, firewall, audit, tasks, and autoruns into `windows_security_posture.json`.

## Success Criteria
- Host profile and patch level captured.
- Security controls and posture documented.
- Misconfigurations recorded with evidence.

## Tool References
- ../toolcards/winpeas.md
- ../toolcards/seatbelt.md
- ../toolcards/powershell.md
- ../toolcards/windows-exploit-suggester.md
