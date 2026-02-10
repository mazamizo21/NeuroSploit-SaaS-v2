# Tool: sqlninja

## Overview
Use sqlninja for targeted SQL Server injection workflows with config files.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Configure target parameters in `sqlninja.conf`.
2. Start with detection/fingerprint modes before exploitation.
3. Log all output for evidence and reproducibility.

## Deep Dives
Load references as needed:
1. ../toolcards/sqlninja.md
2. references/advanced.md

## Evidence Collection
1. sqlninja logs
1. evidence.json with config and mode

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
