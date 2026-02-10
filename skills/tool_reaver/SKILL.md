# Tool: Reaver

## Overview
Use Reaver and wash for scoped WPS assessments.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Use wash to identify WPS-enabled targets and channel constraints.
2. Run Reaver with explicit BSSID/channel targets.
3. Document lockouts or rate-limiting behavior.

## Deep Dives
Load references as needed:
1. ../toolcards/reaver.md
2. references/advanced.md

## Evidence Collection
1. wash output (JSON when available)
1. evidence.json with target and WPS state

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
