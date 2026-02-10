# Tool: Socat

## Overview
Use socat to create scoped relays and port forwards within approved scope.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Define explicit listen and target endpoints.
2. Use `fork` only when multiple connections are required.
3. Record relay configuration and activity for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/socat.md
2. references/advanced.md

## Evidence Collection
1. socat command logs
1. evidence.json with listen/target endpoints

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
