# Tool: sqlmap

## Overview
Use sqlmap for scoped SQLi validation with explicit risk/level controls.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start with conservative `--level`/`--risk` and a single parameter.
2. Use request files (`-r`) to capture complex flows.
3. Enumerate data only after confirmed injection and authorization.

## Deep Dives
Load references as needed:
1. ../toolcards/sqlmap.md
2. references/advanced.md

## Evidence Collection
1. sqlmap output logs and results
1. evidence.json with parameters, level/risk, and findings

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
