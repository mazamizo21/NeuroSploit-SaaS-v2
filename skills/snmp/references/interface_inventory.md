# Interface Inventory

## Goals
1. Capture interface names, speeds, and status.
2. Identify exposed or misconfigured interfaces.
3. Record admin vs operational status.

## Safe Checks
1. `snmpwalk -v2c -c <community> target ifDescr`
2. `snmpwalk -v2c -c <community> target ifOperStatus`
3. `snmpwalk -v2c -c <community> target ifAdminStatus`

## Evidence Checklist
1. Interface list and status summary.
2. Notes on down or unusual interfaces.
3. Admin vs operational status discrepancies.
