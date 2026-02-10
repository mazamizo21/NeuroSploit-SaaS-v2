# Tool: Crunch

## Overview
Use Crunch for controlled wordlist generation with explicit patterns.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Define length bounds and character sets to limit size.
2. Use patterns (`-t`) to reflect realistic formats.
3. Estimate output size before full generation.

## Deep Dives
Load references as needed:
1. ../toolcards/crunch.md
2. references/advanced.md

## Evidence Collection
1. generated wordlists
1. evidence.json with pattern and size estimates

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
