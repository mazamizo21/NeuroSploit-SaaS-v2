# Tool: Sublist3r

## Overview
Use Sublist3r for OSINT subdomain enumeration and optional brute force.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Enumerate with default engines first; add `-e` for specific sources.
2. Enable brute-force (`-b`) only when explicitly authorized.
3. Use port checks (`-p`) sparingly and only for scoped validation.

## Deep Dives
Load references as needed:
1. ../toolcards/sublist3r.md
2. references/advanced.md

## Evidence Collection
1. sublist3r output list
1. evidence.json with engines and brute-force usage

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
