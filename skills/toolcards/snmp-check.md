# snmp-check Toolcard

## Overview
- Summary: snmp-check is an SNMP enumeration script that gathers system information with a single run.

## Advanced Techniques
- Use version-specific flags to match the target SNMP version.
- Combine with `snmpwalk` for targeted OID collection.

## Safe Defaults
- Read-only enumeration only.
- Avoid community guessing unless explicitly authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/hacktrackgnulinux/snmpcheck
