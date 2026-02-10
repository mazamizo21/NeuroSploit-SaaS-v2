# Tool: hping3

## Overview
Use hping3 for scoped packet crafting and service probing.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select a minimal probe (SYN/ACK/ICMP) aligned with the objective.
2. Use scan mode only when explicitly authorized.
3. Capture outputs and correlate with service discovery evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/hping3.md
2. references/advanced.md

## Evidence Collection
1. hping3 output logs
1. evidence.json with probe type + targets

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
