# Tool: netdiscover

## Overview
Use netdiscover for ARP-based host discovery on local segments.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start in passive mode where possible.
2. Use explicit ranges to avoid unintended segments.
3. Record results for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/netdiscover.md
2. references/advanced.md

## Evidence Collection
1. netdiscover output logs
1. evidence.json with mode and subnet

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
