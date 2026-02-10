# SNMP Versioning and Access

## Goals
1. Identify SNMP versions enabled.
2. Capture sysDescr and sysObjectID safely.
3. Record sysName and sysLocation when available.

## Safe Checks
1. `nmap --script snmp-info`
2. `snmpwalk -v2c -c <community> target sysDescr.0`
3. `snmpwalk -v2c -c <community> target sysName.0`

## Evidence Checklist
1. Version and sysDescr output.
2. sysObjectID and sysName values.
3. sysLocation if exposed.
