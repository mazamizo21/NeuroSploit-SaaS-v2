# Tool: Bully

## Overview
Use Bully for WPS testing with explicit targeting and timeboxing.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Confirm PixieWPS is available if offline attacks are in scope.
2. Set channel and BSSID explicitly.
3. Use lock detection options to avoid excessive retries.

## Deep Dives
Load references as needed:
1. ../toolcards/bully.md
2. references/advanced.md

## Evidence Collection
1. bully output logs
1. evidence.json with options and results

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
