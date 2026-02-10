# Tool: Ettercap

## Overview
Use Ettercap for authorized MITM testing with explicit targets and filters.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select a specific MITM mode and define exact target pairs.
2. Use filters only when necessary and keep them minimal.
3. Capture logs and evidence of observed traffic within scope.

## Deep Dives
Load references as needed:
1. ../toolcards/ettercap.md
2. references/advanced.md

## Evidence Collection
1. ettercap logs
1. evidence.json with mode and target pairs

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
