# Tool: DIRB

## Overview
Use DIRB for scoped wordlist-based content discovery.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select wordlists that match the target stack and size constraints.
2. Limit extensions to relevant file types.
3. Record outputs for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/dirb.md
2. references/advanced.md

## Evidence Collection
1. dirb output logs
1. evidence.json with wordlist and extensions

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
