# Tool: Rubeus

## Overview
Use Rubeus for Kerberos ticket abuse only when explicitly authorized.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Identify the Kerberos technique needed (kerberoast, asreproast, s4u).
2. Run the minimal command to validate the path.
3. Capture tickets and hash outputs for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/rubeus.md
2. references/advanced.md

## Evidence Collection
1. ticket artifacts (kirbi) or hash outputs
1. evidence.json with technique + target

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
