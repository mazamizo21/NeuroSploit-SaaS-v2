# Tool: Gobuster

## Overview
Use Gobuster for scoped directory, DNS, and vhost enumeration.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Choose the appropriate mode (dir, dns, vhost) for the target.
2. Use curated wordlists and keep concurrency reasonable.
3. Limit extensions and paths to reduce noise.

## Deep Dives
Load references as needed:
1. ../toolcards/gobuster.md
2. references/advanced.md

## Evidence Collection
1. gobuster output files
1. evidence.json with mode, wordlist, and extensions

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
