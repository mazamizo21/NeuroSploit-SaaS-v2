# Tool: Feroxbuster

## Overview
Use Feroxbuster for recursive directory/content discovery with scoped filters.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start with a minimal wordlist and extensions.
2. Use filters to exclude noisy status codes.
3. Enable recursion only within scope and time limits.

## Deep Dives
Load references as needed:
1. ../toolcards/feroxbuster.md
2. references/advanced.md

## Evidence Collection
1. feroxbuster output files
1. evidence.json with extensions and filters

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
