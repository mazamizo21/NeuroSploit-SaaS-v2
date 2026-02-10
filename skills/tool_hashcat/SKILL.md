# Tool: Hashcat

## Overview
Use Hashcat for structured password recovery with explicit hash modes.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Identify hash mode before cracking.
2. Use dictionary and rule-based attacks before mask/brute-force.
3. Record recovered credentials and attack parameters.

## Deep Dives
Load references as needed:
1. ../toolcards/hashcat.md
2. references/advanced.md

## Evidence Collection
1. hashcat session logs
1. evidence.json with mode and attack type

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
