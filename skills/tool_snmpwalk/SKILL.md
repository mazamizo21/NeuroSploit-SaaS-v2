# Tool: snmpwalk

## Overview
Use snmpwalk to enumerate SNMP MIB trees within scope.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start with a scoped OID or default MIB-2 subtree.
2. Use the correct SNMP version and community string.
3. Record walked OIDs and relevant output.

## Deep Dives
Load references as needed:
1. ../toolcards/snmpwalk.md
2. references/advanced.md

## Evidence Collection
1. snmpwalk output logs
1. evidence.json with version, community, and OID

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
