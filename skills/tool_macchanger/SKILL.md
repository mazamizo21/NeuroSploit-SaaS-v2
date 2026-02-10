# Tool: macchanger

## Overview
Use macchanger to alter MAC addresses only when explicitly authorized.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Record the current MAC address before any changes.
2. Apply a randomized or vendor-based MAC per scope rules.
3. Revert to the original MAC when testing is complete.

## Deep Dives
Load references as needed:
1. ../toolcards/macchanger.md
2. references/advanced.md

## Evidence Collection
1. before/after MAC output
1. evidence.json with interface + change rationale

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
