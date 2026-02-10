# Tool: Fierce

## Overview
Use Fierce to locate related hosts and IP space via DNS reconnaissance.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Seed with known subdomains and expand cautiously.
2. Use traversal (`--traverse`) only within authorized IP ranges.
3. Use `--connect` to validate live hosts when approved.

## Deep Dives
Load references as needed:
1. ../toolcards/fierce.md
2. references/advanced.md

## Evidence Collection
1. fierce output logs
1. evidence.json with domain, subdomains, and traversal settings

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
