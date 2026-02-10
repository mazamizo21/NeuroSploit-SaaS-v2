# SNMP Service Skill

## Overview
Service-first methodology for SNMP enumeration and safe configuration validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and subnets.
2. External targets: no community guessing or brute force unless explicit authorization is confirmed.
3. Use read-only queries; do not use SNMP write operations.
4. Exploit or write actions require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Discovery and Versioning
- Identify SNMP versions and exposed UDP/TCP 161/162 services.
- Use safe discovery scripts to capture sysDescr and sysObjectID.

### 2. Access Validation
- Test only provided community strings.
- Record authentication success or failure once per host.

### 3. Safe Enumeration (Authorized)
- Walk system and interface OIDs for inventory.
- Use bulk walks for large tables with limits to avoid excessive load.

### 4. Risky Exposure Checks
- Identify default community strings only when explicitly authorized.
- Flag sensitive OIDs exposed (user lists, routing tables, configs).

## Deep Dives
Load references when needed:
1. Versioning and access: `references/versioning.md`
2. Community strings (explicit-only): `references/community_strings.md`
3. Sensitive OID exposure: `references/sensitive_oids.md`
4. Interface inventory: `references/interface_inventory.md`

## Service-First Workflow (Default)
1. Discovery: `nmap` SNMP scripts for sysDescr and version.
2. Access validation: `snmpwalk` on system OIDs with provided community.
3. Authorized enrichment: `snmp-check` for structured output.
4. Explicit-only: community discovery with `onesixtyone` or any write tests.

## Evidence Collection
1. `snmp_inventory.json` with versions, sysDescr, interfaces summary (parsed from `snmpwalk` output).
2. `evidence.json` with raw `snmpwalk` output and command metadata.
3. `findings.json` with exposed data or weak community evidence.

## Evidence Consolidation
Use `parse_snmpwalk.py` to convert `snmpwalk` output into `snmp_inventory.json`.

## Success Criteria
- SNMP version and access level confirmed.
- Key system OIDs enumerated safely.
- Risky exposures documented with evidence.

## Tool References
- ../toolcards/snmpwalk.md
- ../toolcards/snmp-check.md
- ../toolcards/onesixtyone.md
- ../toolcards/nmap.md
