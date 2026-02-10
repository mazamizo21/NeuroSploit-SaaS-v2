# Tool: arping

## Overview
Use arping for host reachability checks on local networks.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select the correct interface and send limited probes.
2. Record MAC responses and timings.
3. Use for validation rather than broad scanning.

## Deep Dives
Load references as needed:
1. ../toolcards/arping.md
2. references/advanced.md

## Evidence Collection
1. arping output logs
1. evidence.json with interface and target

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
