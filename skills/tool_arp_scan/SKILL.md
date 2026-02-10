# Tool: arp-scan

## Overview
Use arp-scan for scoped Layer-2 discovery on authorized segments.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select the correct interface and subnet.
2. Use --localnet for the directly attached segment when appropriate.
3. Save output for evidence and correlation with other scans.

## Deep Dives
Load references as needed:
1. ../toolcards/arp-scan.md
2. references/advanced.md

## Evidence Collection
1. arp-scan output logs
1. evidence.json with interface and subnet

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
