# Linux Host Validation Skill

## Overview
Service-first methodology for Linux host security validation with safe, read-only checks by default.

## Scope Rules
1. Only operate on explicitly authorized Linux hosts.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Do not change system settings, create accounts, or modify policies without authorization.
4. Treat host output as sensitive; collect only evidence required for remediation.

## Methodology

### 1. System Profile and Patch Level
- Capture OS distribution, kernel version, and patch level.
- Record installed package manager and repository configuration.

### 2. Identity and Privilege Context
- Record current user, groups, and sudo privileges.
- Identify local admin membership and delegated rights.

### 3. Security Controls and Hardening
- Check firewall status, SELinux/AppArmor modes, and audit logging.
- Validate SSH configuration and PAM policies.

### 4. Misconfiguration and Exposure Checks
- Identify writable system paths, risky SUID/SGID binaries, and weak sudo rules.
- Review cron jobs, systemd services, and startup scripts.

### 5. Explicit-Only Actions
- Credential access, exploit attempts, or persistence actions require explicit authorization.

## Deep Dives
Load references when needed:
1. Hardening validation: `references/hardening.md`
2. Misconfiguration triage: `references/misconfig_triage.md`
3. Logging and audit: `references/logging_audit.md`
4. SSH hardening: `references/ssh_hardening.md`
5. Filesystem permissions: `references/filesystem_permissions.md`

## Service-First Workflow (Default)
1. Inventory: `uname -a`, `lsb_release`, and `id`/`sudo -l` queries.
2. Read-only posture checks: `lynis` and `linpeas` scoped runs.
3. Optional patch correlation: `linux-exploit-suggester` for advisory mapping.
4. Explicit-only: credential access or exploit validation.

## Evidence Collection
1. `linux_host_inventory.json` with OS, kernel, and identity summary.
2. `linux_security_posture.json` with controls and hardening checks.
3. `evidence.json` with raw posture outputs and command logs.
4. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `merge_posture.py` to consolidate inventory, firewall, auditd, sshd, sudoers, and cron evidence into `linux_security_posture.json`.

## Success Criteria
- Host profile and patch level captured.
- Security controls and posture documented.
- Misconfigurations recorded with evidence.

## Tool References
- ../toolcards/linpeas.md
- ../toolcards/lynis.md
- ../toolcards/linux-exploit-suggester.md
