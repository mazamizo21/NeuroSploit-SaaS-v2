# Tool: SharpHound

## Overview
Collect scoped AD data with SharpHound and feed it to BloodHound CE.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select the minimal collection methods needed (e.g., Session, LocalAdmin, ACL).
2. Apply scope limits (domain/OU filters, timeboxes) before collection.
3. Collect, compress, and transfer output to analysis host.
4. Validate collection size and integrity before ingesting to BloodHound.

## Deep Dives
Load references as needed:
1. ../toolcards/sharphound.md
2. references/advanced.md

## Evidence Collection
1. SharpHound zip output
1. evidence.json with collection scope + method list

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
