# Tool: hash-identifier

## Overview
Use hash-identifier to quickly classify hash formats before cracking.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Paste hash samples and record candidate types.
2. Cross-check with hashcat/john format lists.
3. Document likely formats used for cracking decisions.

## Deep Dives
Load references as needed:
1. ../toolcards/hash-identifier.md
2. references/advanced.md

## Evidence Collection
1. hash identification notes
1. evidence.json with candidate formats

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
