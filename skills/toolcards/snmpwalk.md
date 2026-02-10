# snmpwalk Toolcard

## Overview
- Summary: snmpwalk (Net-SNMP) walks an SNMP subtree using GETNEXT requests to retrieve management data.

## Advanced Techniques
- Use SNMPv3 where available for auth and privacy.
- Prefer `snmpbulkwalk` for large tables to reduce request count.

## Safe Defaults
- Read-only communities only; avoid write operations.
- Limit walk scope to required OIDs to reduce load.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.net-snmp.org/docs/man/snmpwalk.html
