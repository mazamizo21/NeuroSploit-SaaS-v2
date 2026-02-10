# Tool: Proxychains

## Overview
Use proxychains to route tools through approved proxy infrastructure.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Configure the proxy list in `proxychains.conf`.
2. Select strict or dynamic chain mode based on reliability needs.
3. Record proxy endpoints and results for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/proxychains.md
2. references/advanced.md

## Evidence Collection
1. proxychains run logs
1. evidence.json with proxy chain configuration

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
