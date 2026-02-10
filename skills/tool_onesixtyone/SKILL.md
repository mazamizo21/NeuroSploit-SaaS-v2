# Tool: onesixtyone

## Overview
Use onesixtyone to validate SNMP community strings within scope.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Use a limited target list and curated community list.
2. Tune wait times (`-w`) to avoid packet loss.
3. Record successful community strings for follow-up enumeration.

## Deep Dives
Load references as needed:
1. ../toolcards/onesixtyone.md
2. references/advanced.md

## Evidence Collection
1. onesixtyone output logs
1. evidence.json with targets and community list

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
