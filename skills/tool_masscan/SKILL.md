# Tool: Masscan

## Overview
Use Masscan for fast port discovery with strict rate controls.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Define a minimal port set and target range.
2. Set a conservative `--rate` and timebox the scan.
3. Export results to structured output and hand off to validation tools.

## Deep Dives
Load references as needed:
1. ../toolcards/masscan.md
2. references/advanced.md

## Evidence Collection
1. masscan output files
1. evidence.json with rate settings and port ranges

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
