# Tool: Wfuzz

## Overview
Use Wfuzz for structured fuzzing with payloads and filters.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Define payloads and a single fuzz point.
2. Use filters (status/length/words) to reduce noise.
3. Timebox fuzzing to avoid excessive load.

## Deep Dives
Load references as needed:
1. ../toolcards/wfuzz.md
2. references/advanced.md

## Evidence Collection
1. wfuzz output files
1. evidence.json with payloads and filters

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
