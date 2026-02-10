# Tool: DNSChef

## Overview
Use DNSChef to proxy or spoof DNS responses for controlled analysis.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Run in proxy mode first to observe traffic.
2. Define fake domains or IPs only when authorized.
3. Log DNS activity for evidence and auditing.

## Deep Dives
Load references as needed:
1. ../toolcards/dnschef.md
2. references/advanced.md

## Evidence Collection
1. dnschef logs
1. evidence.json with fake/truedomain settings

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
