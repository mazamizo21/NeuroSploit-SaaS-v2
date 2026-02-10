# Tool: Bettercap

## Overview
Use Bettercap caplets to run scoped network monitoring or MITM tests.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start with passive modules (net.probe, net.recon) before active ones.
2. Use caplets for repeatable sequences and log outputs.
3. Disable modules immediately after validation.

## Deep Dives
Load references as needed:
1. ../toolcards/bettercap.md
2. references/advanced.md

## Evidence Collection
1. bettercap session logs
1. evidence.json with caplets/modules used

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
