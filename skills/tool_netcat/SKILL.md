# Tool: Netcat

## Overview
Use netcat for scoped connectivity checks and controlled data transfers.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Validate connectivity with `-v`/`-z` before data transfer.
2. Use explicit ports and timeouts to avoid lingering sessions.
3. Capture outputs and transfer logs for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/netcat.md
2. references/advanced.md

## Evidence Collection
1. netcat command logs
1. evidence.json with hosts, ports, and transfer context

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
