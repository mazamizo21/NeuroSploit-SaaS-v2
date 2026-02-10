# Tool: dnsenum

## Overview
Use dnsenum for DNS enumeration with optional whois and reverse lookups.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start with default enumeration and skip reverse lookups if not required.
2. Enable brute-force with curated wordlists only when authorized.
3. Record output for evidence and correlation with other DNS tools.

## Deep Dives
Load references as needed:
1. ../toolcards/dnsenum.md
2. references/advanced.md

## Evidence Collection
1. dnsenum output logs
1. evidence.json with options used and outputs

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
