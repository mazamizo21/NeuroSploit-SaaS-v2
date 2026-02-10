# Tool: mitm6

## Overview
Use mitm6 to coerce authentication in IPv6-enabled AD networks.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Scope the domain and interface before activation.
2. Coordinate with relay tooling (e.g., ntlmrelayx) if authorized.
3. Timebox the attack window and capture evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/mitm6.md
2. references/advanced.md

## Evidence Collection
1. mitm6 logs showing coerced auth
1. evidence.json with victims and relay targets

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
