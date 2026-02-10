# Tool: Hydra

## Overview
Use Hydra for scoped credential validation with explicit rate controls.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select the correct module/protocol and define success/failure conditions.
2. Set conservative task/thread limits to avoid lockouts.
3. Record valid credentials and stop on success when appropriate.

## Deep Dives
Load references as needed:
1. ../toolcards/hydra.md
2. references/advanced.md

## Evidence Collection
1. hydra output logs
1. evidence.json with protocol, rate, and results

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
