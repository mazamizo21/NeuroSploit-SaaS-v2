# Defense Evasion Skill

## Overview
Evaluate evasion risks in a non-destructive manner with evidence-only validation, focusing on visibility gaps and control coverage.

## Scope Rules
1. Only operate on explicitly authorized systems.
2. External targets: evasion actions require explicit authorization (external_exploit=explicit_only).
3. If defense evasion is disabled for the job, do **evidence-only** validation (no changes).
4. If enabled, use **minimal, reversible** cleanup steps and document everything.

## Methodology

### 1. Control Inventory
- Identify security agents, logging daemons, and monitoring coverage.
- Record active defenses and service status.

### 2. Logging Coverage
- Verify audit logging, retention, and forwarding coverage.
- Identify gaps in event logging or missing sources.

### 3. Tamper Protection
- Review permissions and protections that prevent control disablement.
- Document weak configurations without changing them.

### 4. Safe Validation
- Capture configuration evidence only.
- Avoid changes to EDR/AV or logging settings.

### 5. Cleanup (Only If Enabled)
- Remove temporary artifacts created by the test.
- Clear only the specific test logs you generated (no broad log wipes).
- Tag MITRE: T1070 (Indicator Removal), T1562 (Impair Defenses).

## Deep Dives
Load references when needed:
1. Logging gaps: `references/logging_gaps.md`
2. Windows logging coverage: `references/windows_logging.md`
3. Linux auditd coverage: `references/linux_auditd.md`
4. SIEM ingestion checks: `references/siem_ingestion.md`
5. EDR/AV status: `references/edr_av_status.md`
6. Tamper protection: `references/tamper_protection.md`
7. Explicit-only actions: `references/explicit_only_actions.md`

## Evidence Collection
1. `defense_controls.json` with security agents and monitoring coverage.
2. `logging_coverage.json` with audit/retention/forwarding status.
3. `tamper_protection.json` with control protection evidence.
4. `evidence.json` with raw outputs and command logs.
5. `findings.json` with evasion risks.
6. `cleanup.json` with all cleanup steps performed (if enabled).

## Evidence Consolidation
Use `summarize_defense_controls.py` to normalize control coverage notes into `defense_controls.json`.

## Success Criteria
- Control coverage documented with evidence.
- Evasion risks documented without changes.
