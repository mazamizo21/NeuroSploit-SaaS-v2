# Tool: Wireshark

## Overview
Analyze captured traffic in Wireshark with scoped display filters.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Open the capture file and apply display filters to isolate relevant traffic.
2. Inspect protocol details and follow streams as needed.
3. Export relevant objects or conversations for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/wireshark.md
2. references/advanced.md

## Evidence Collection
1. filtered pcap snapshots or exports
1. evidence.json with display filters and findings

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
