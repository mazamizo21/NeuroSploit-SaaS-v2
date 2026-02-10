# Tool: snmp-check

## Overview
Use snmp-check for readable SNMP enumeration after validating access.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Validate community strings before running enumeration.
2. Use `-w` to detect write access only when explicitly authorized.
3. Capture output sections for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/snmp-check.md
2. references/advanced.md

## Evidence Collection
1. snmp-check output logs
1. evidence.json with version/community and write checks

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
