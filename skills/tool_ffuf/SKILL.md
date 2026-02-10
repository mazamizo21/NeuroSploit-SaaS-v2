# Tool: ffuf

## Overview
Use ffuf for targeted fuzzing with explicit matchers and filters.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Define a single fuzz point and select a scoped wordlist.
2. Use matchers/filters to reduce noise.

## Deep Dives
Load references as needed:
1. ../toolcards/ffuf.md
2. references/advanced.md

## Evidence Collection
1. ffuf result files (json/csv)
1. evidence.json with matchers and filters

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
