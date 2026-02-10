# LDAP Service Skill

## Overview
Service-specific methodology for LDAP and Active Directory enumeration with safe, read-only validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts, domains, and naming contexts.
2. External targets: no brute force or user enumeration unless explicit authorization is confirmed.
3. Use read-only queries and avoid modifying directory objects.
4. Exploit or write operations require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. RootDSE and Naming Contexts
- Query RootDSE to identify naming contexts and supported features.
- Record supported LDAP versions and SASL mechanisms.

### 2. Secure Transport Validation
- Prefer LDAPS or StartTLS when available.
- Capture TLS protocol and cipher details when possible.

### 3. Authentication and Access Validation
- Use provided credentials only.
- Record bind success/failure without repeated attempts.

### 4. Directory Enumeration (Authorized)
- Enumerate users, groups, and computers with scoped filters.
- Use paging or size limits to avoid excessive load.

### 5. Safe Configuration Checks
- Check for anonymous bind exposure and overly broad read access.
- Flag sensitive attributes exposed without authorization.

## Service-First Workflow (Default)
1. Discovery: RootDSE and naming contexts via `ldapsearch` or `nmap` scripts.
2. Access validation: one bind attempt with provided credentials only.
3. Authorized enrichment: scoped dumps with `ldapdomaindump` and AD-integrated DNS with `adidnsdump`.
4. Explicit-only deep checks: high-volume enumeration or any write operations only when authorization is confirmed.

## Deep Dives
Load references when needed:
1. RootDSE attributes and naming contexts: `references/rootdse.md`
2. Anonymous bind validation: `references/anonymous_bind.md`
3. AD-safe enrichment patterns: `references/ad_enrichment.md`

## Evidence Collection
1. `ldap_rootdse.json` with naming contexts and server capabilities (parsed from LDIF).
2. `ldap_objects.json` with summarized directory objects.
3. `evidence.json` with raw LDIF outputs and bind evidence.
4. `findings.json` with risky access evidence.

## Evidence Consolidation
Use `parse_ldapsearch.py` to convert RootDSE LDIF output into `ldap_rootdse.json`.

## Success Criteria
- RootDSE and naming contexts captured.
- Key directory objects enumerated safely.
- Risky access documented with evidence.

## Tool References
- ../toolcards/ldapsearch.md
- ../toolcards/ldapdomaindump.md
- ../toolcards/adidnsdump.md
- ../toolcards/nmap.md
