# Tool: Responder

## Overview
Use Responder for scoped name-resolution poisoning and credential capture.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start in Analyze mode to confirm traffic without active poisoning.
2. Enable only the minimum protocols needed to validate the attack path.
3. Collect hashes and verify storage locations for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/responder.md
2. references/advanced.md

## Evidence Collection
1. captured hash logs
1. evidence.json with victim host + protocol

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
