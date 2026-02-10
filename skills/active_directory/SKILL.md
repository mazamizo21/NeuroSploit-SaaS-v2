# Active Directory Skill

## Overview
Service-specific workflows for Active Directory domain discovery, enumeration, and risk validation across LDAP, Kerberos, SMB, and ADCS.

## Scope Rules
1. Operate only on in-scope domain controllers, hosts, and domains.
2. External targets: no password spraying or exploitation without explicit authorization.
3. Prefer read-only queries and minimize directory impact.
4. Any write actions, persistence, or lateral movement require explicit authorization.

## Methodology

### 1. Domain Discovery
- Identify the domain/forest, domain controllers, sites, and trusts.
- Capture RootDSE naming contexts and SMB domain info.

### 2. Authentication Validation
- Validate provided credentials only.
- Log successes/failures once; do not brute force.

### 3. Directory Enumeration (Authorized)
- Enumerate users, groups, computers, and privileged groups.
- Collect SPNs, delegation flags, and GPO identifiers.

### 4. Kerberos + ADCS Checks (Authorized)
- Check pre-auth configuration, delegation exposures, and PKI template risks.
- Record any high-risk configurations, not exploitation steps.

### 5. Lateral Movement Prep (Explicit Only)
- Map attack paths and reachable assets (BloodHound/SharpHound).
- Do not execute lateral movement unless explicitly authorized.

## Service-First Workflow (Default)
1. Confirm domain context via RootDSE or SMB/NetBIOS.
2. Capture lightweight inventory (users/groups/computers).
3. If authorized, run path mapping (BloodHound) and privilege review.
4. If ADCS present, enumerate templates and note risky ones.

## Deep Dives
Load references when needed:
1. Domain discovery and inventory: `references/domain_discovery.md`
2. Kerberos + ADCS checks: `references/kerberos_adcs.md`
3. Privileged access review: `references/privileged_access.md`

## Evidence Collection
1. `ad_summary.json` with domain/forest/DCs/sites/trusts.
2. `ad_users.json`, `ad_groups.json`, `ad_computers.json` inventories.
3. `ad_paths.json` with path findings from BloodHound (if run).
4. `evidence.json` with raw outputs and command logs.
5. `findings.json` with risk summaries and affected objects.

## Evidence Consolidation
Normalize ldapdomaindump and BloodHound outputs into `ad_summary.json` and `ad_paths.json`.

## Success Criteria
- Domain context and controllers identified.
- Privileged groups and risky configs documented.
- Attack paths summarized with evidence.

## Tool References
- ../toolcards/ldapsearch.md
- ../toolcards/ldapdomaindump.md
- ../toolcards/kerbrute.md
- ../toolcards/bloodhound.md
- ../toolcards/sharphound.md
- ../toolcards/certipy.md
- ../toolcards/certify.md
- ../toolcards/powerview.md
- ../toolcards/rubeus.md
- ../toolcards/netexec.md
- ../toolcards/crackmapexec.md
- ../toolcards/secretsdump.py.md
- ../toolcards/rpcclient.md
- ../toolcards/smbmap.md
- ../toolcards/gpp-decrypt.md
