# Tool: Nikto

## Overview
Use Nikto to identify known web server issues with tuned checks.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select tuning options to limit test classes.
2. Run against specific ports/hosts within scope.
3. Export structured reports for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/nikto.md
2. references/advanced.md

## Evidence Collection
1. nikto reports (txt/html)
1. evidence.json with tuning options and targets

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
