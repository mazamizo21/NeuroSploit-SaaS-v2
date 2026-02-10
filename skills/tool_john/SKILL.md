# Tool: John the Ripper

## Overview
Use John for scoped password cracking with explicit formats and rules.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Identify hash formats before cracking.
2. Use wordlists and rules before incremental modes.
3. Capture cracked credentials with timestamps.

## Deep Dives
Load references as needed:
1. ../toolcards/john.md
2. references/advanced.md

## Evidence Collection
1. john session logs
1. evidence.json with hash format and rule usage

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
