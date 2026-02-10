# Tool: Mimikatz

## Overview
Use Mimikatz to validate credential access paths within scope.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Confirm authorization for credential access before execution.
2. Run the minimum required modules to validate access.
3. Capture output and redact sensitive values in reports.

## Deep Dives
Load references as needed:
1. ../toolcards/mimikatz.md
2. references/advanced.md

## Evidence Collection
1. redacted credential output
1. evidence.json with module + target

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
