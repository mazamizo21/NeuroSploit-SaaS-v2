# Tool: DMitry

## Overview
Use DMitry for quick OSINT checks on domains and hosts.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select only the required options (whois, subdomains, email, ports).
2. Use short timeouts for port scans to avoid noise.
3. Save output files for evidence and correlation.

## Deep Dives
Load references as needed:
1. ../toolcards/dmitry.md
2. references/advanced.md

## Evidence Collection
1. dmitry output file
1. evidence.json with flags and target

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
