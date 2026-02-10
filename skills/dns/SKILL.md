# DNS Service Skill

## Overview
Service-specific methodology for DNS enumeration, subdomain discovery, and safe configuration checks.

## Scope Rules
1. Only operate on explicitly in-scope domains and name servers.
2. External targets: avoid brute-force enumeration unless explicit authorization is confirmed.
3. Use conservative rate limits when querying authoritative servers.

## Methodology

### 1. Baseline Record Collection
- Identify authoritative name servers and SOA data.
- Collect A, AAAA, MX, TXT, and CNAME records for known domains.

### 2. Zone Transfer Attempt (Authorized)
- Attempt AXFR only against in-scope authoritative servers.
- Record results and stop if refused.

### 3. Subdomain Enumeration
- Use passive sources first.
- Use active brute-force only with explicit authorization.

### 4. Resolution Validation
- Resolve discovered names and deduplicate.
- Identify dangling records or misrouted CNAMEs.

### 5. Safe Configuration Checks
- Review SPF, DKIM, and DMARC records.
- Check for DNSSEC presence and basic consistency.

## Deep Dives
Load references when needed:
1. Authority and SOA: `references/authority_and_soa.md`
2. Zone transfer checks: `references/zone_transfer.md`
3. Email security records: `references/email_security.md`
4. DNSSEC posture: `references/dnssec.md`
5. Dangling CNAME checks: `references/dangling_cname.md`

## Evidence Collection
1. `dns_records.json` with discovered records and authority data (parsed from `dig` output).
2. `subdomains.json` with resolved hosts and IPs.
3. `evidence.json` with raw `dig` outputs, resolver notes, and timestamps.
4. `findings.json` with misconfigurations or risky records.

## Evidence Consolidation
Use `parse_dig.py` to convert `dig` outputs into `dns_records.json`.

## Success Criteria
- Authoritative servers identified.
- Subdomains enumerated and validated.
- Configuration risks documented with evidence.

## Tool References
- ../toolcards/dnsrecon.md
- ../toolcards/dnsenum.md
- ../toolcards/amass.md
- ../toolcards/subfinder.md
