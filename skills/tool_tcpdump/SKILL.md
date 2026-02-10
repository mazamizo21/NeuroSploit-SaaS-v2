# Tool: tcpdump

## Overview
Capture targeted network traffic with tcpdump and preserve pcaps for analysis.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select the correct interface and apply a scoped capture filter.
2. Timebox the capture and write to pcap for evidence.
3. Validate the capture by reading the pcap in a safe environment.

## Deep Dives
Load references as needed:
1. ../toolcards/tcpdump.md
2. references/advanced.md

## Evidence Collection
1. pcap files with scoped traffic
1. evidence.json with filter, interface, and time window

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
