# Tool: Medusa

## Overview
Use Medusa for scoped parallel login testing with careful throttling.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select service modules explicitly and validate connectivity first.
2. Control thread count to avoid lockouts.
3. Log results and stop after confirmed success.

## Deep Dives
Load references as needed:
1. ../toolcards/medusa.md
2. references/advanced.md

## Evidence Collection
1. medusa output logs
1. evidence.json with module, targets, and rate limits

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
