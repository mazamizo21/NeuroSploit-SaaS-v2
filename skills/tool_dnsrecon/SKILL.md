# Tool: dnsrecon

## Overview
Use dnsrecon for structured DNS enumeration with controlled query types.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Run a standard enumeration (SOA/NS/A/AAAA/MX/SRV) first.
2. Use targeted brute force or reverse lookups only when scoped and necessary.
3. Check for zone transfers only against authorized name servers.

## Deep Dives
Load references as needed:
1. ../toolcards/dnsrecon.md
2. references/advanced.md

## Evidence Collection
1. dnsrecon output files (xml/csv/json)
1. evidence.json with enum type and data sources

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
