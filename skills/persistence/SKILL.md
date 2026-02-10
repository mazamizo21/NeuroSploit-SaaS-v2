# Persistence Skill

## Overview
Assess persistence risks in a controlled, non-destructive manner with evidence-only validation and strict scoping.

## Scope Rules
1. Only operate on explicitly authorized systems.
2. External targets: persistence actions require explicit authorization (external_exploit=explicit_only).
3. If persistence is disabled for the job, do **evidence-only** validation (no changes).
4. If persistence is enabled, use **minimal, reversible** changes and document cleanup steps.

## Methodology

### 1. Baseline Host Context
- Confirm OS family, user context, and available services.
- Record relevant host metadata for evidence.

### 2. Windows Persistence Surface
- Review services, scheduled tasks, registry run keys, and startup folders.
- Check WMI persistence and Winlogon/LSA provider settings.

### 3. Linux Persistence Surface
- Review systemd units, cron jobs, init scripts, and shell profile hooks.
- Check SSH authorized keys and profile scripts for persistence hooks.

### 4. Evidence-Only Validation (Default)
- Capture configuration evidence and permissions.
- Avoid file modifications or new entries.

### 5. Minimal Persistence (Only If Enabled)
- Linux: create a simple systemd unit or cron entry (document and remove after validation).
- Windows: scheduled task or Run key entry (document and remove after validation).
- Tag MITRE: T1053 (Scheduled Task/Job), T1547 (Boot/Logon Autostart).

## Deep Dives
Load references when needed:
1. Windows autorun locations: `references/windows_autoruns.md`
2. Windows services and tasks: `references/windows_services.md`
3. Windows registry persistence: `references/windows_registry.md`
4. Windows WMI persistence: `references/windows_wmi.md`
5. Linux persistence paths: `references/linux_persistence_paths.md`
6. Linux systemd units: `references/linux_systemd.md`
7. Linux cron and timers: `references/linux_cron.md`
8. Linux shell profiles: `references/linux_shell_profiles.md`
9. Linux SSH keys: `references/linux_ssh_keys.md`
10. Explicit-only actions: `references/explicit_only_actions.md`

## Evidence Collection
1. `persistence.json` with summarized persistence evidence.
2. `persistence_inventory.json` with paths, tasks, services, and owners.
3. `persistence_risks.json` with risky locations or misconfigurations.
4. `evidence.json` with raw outputs and command logs.
5. `findings.json` with risk notes and remediation guidance.
6. `handoff.json` with any interactive access commands created during persistence validation.

## Evidence Consolidation
Use `normalize_persistence.py` to convert structured notes into `persistence_inventory.json`.
Summarize key risks into `persistence_risks.json`.

## Success Criteria
- Persistence locations inventoried safely.
- Risks documented with evidence.
- No unauthorized changes performed.
