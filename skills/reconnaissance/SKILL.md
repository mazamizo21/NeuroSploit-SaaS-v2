---
name: reconnaissance
description: Systematic information gathering about target infrastructure and services. Covers passive OSINT, semi-passive web recon, and active scanning with a structured workflow.
---

# Reconnaissance Skill

## Overview
Systematic information gathering about target infrastructure and services.
Covers passive OSINT, semi-passive web recon, and active scanning with
a structured workflow: passive first → semi-passive → active last.

## Scope Rules
1. Only operate on explicitly in-scope targets.
2. External targets: avoid aggressive scans and brute force unless explicitly authorized.
3. Prefer passive sources and conservative rate limits.
4. If scope expansion is enabled (lab), map adjacent/internal subnets to support lateral movement.

---

## Recon Depth Levels

| Level | Time | Use When | Tools |
|-------|------|----------|-------|
| **Quick** | 5 min | CTF, time-boxed, initial triage | `nmap --top-ports 100`, `whatweb`, `curl -sI`, `dig` |
| **Standard** | 30 min | Typical engagement target | `nmap -sV -sC`, `subfinder`, `gobuster dir`, `ffuf`, `waybackurls` |
| **Deep** | 2hr+ | Primary target, full assessment | All of the above + `amass`, `nuclei`, `cloud_enum`, JS analysis, API recon, Shodan/Censys correlation, source map extraction |

---

## Methodology

### Recon Workflow (Phase Order)
```
Phase 1: PASSIVE 🟢  → OSINT, public records, no target interaction
Phase 2: SEMI-PASSIVE 🟡 → DNS queries, cert logs, cached data
Phase 3: ACTIVE 🔴   → Port scans, directory brute-force, direct probing
```
OPSEC tiers (🟢🟡🔴) are marked throughout. See `references/opsec_recon.md` for details.
Always exhaust passive sources before moving to active scanning.

### 1. Scope Normalization
- Normalize targets to canonical host/port/URL lists.
- Deduplicate and respect allowlists.
- Identify root domains, subdomains, IP ranges, and ASNs.

### 2. Network Discovery
- Identify active hosts and open services.
- Use conservative scan rates and limited retries.
- Start with top ports, expand to full range if authorized.

### 3. Service Mapping
- Capture service banners, versions, and protocols.
- Correlate evidence into a service inventory.
- Flag known-vulnerable versions against CVE databases.

### 4. Web Recon
- Discover endpoints and technology stacks safely.
- Capture screenshots only when authorized.
- Enumerate parameters, APIs, and hidden functionality.

---

## OSINT Methodology (Passive)

### Google Dorking
```
site:target.com filetype:pdf          # documents
site:target.com filetype:xlsx         # spreadsheets
site:target.com inurl:admin           # admin panels
site:target.com intitle:"index of"    # directory listings
site:target.com ext:sql | ext:bak     # database/backup files
site:target.com intext:"password"     # credential leaks
"target.com" site:pastebin.com        # paste sites
"target.com" site:github.com          # code leaks
```

### Shodan / Censys
- **Shodan:** `shodan search 'hostname:target.com'` or `shodan host <IP>`
- **Censys:** `censys search 'services.tls.certificates.leaf.names: target.com'`
- Search for exposed services, default credentials, IoT devices.
- Look for `http.title`, `ssl.cert.subject.CN`, open ports.

### Certificate Transparency
- **crt.sh:** `curl -s 'https://crt.sh/?q=%.target.com&output=json' | jq '.[].name_value' | sort -u`
- Discover subdomains from certificate logs.
- Cross-reference with DNS to find live hosts.

### GitHub Secret Scanning
```bash
# Search for leaked secrets in repos
# Use GitHub search: "target.com" password OR secret OR api_key
# Tools: trufflehog, gitleaks
trufflehog github --org=target-org --only-verified
gitleaks detect --source=/path/to/repo --report-format=json
```

### LinkedIn / Employee Enumeration
- Map org chart: executives, IT staff, developers.
- Build email patterns: first.last@target.com, f.last@target.com.
- Use for password spraying wordlists and phishing pretexts.

### Email Harvesting
```bash
theHarvester -d target.com -b all -l 500     # multi-source harvest
# hunter.io — verify email patterns (API key required)
# phonebook.cz — free email/domain search
```

---

## Web Recon Deep Dive (Semi-Passive → Active)

### Content Discovery
```bash
# Directory brute-force
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -t 50 -o dirs.txt
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403
dirsearch -u http://target -e php,html,js,txt -x 400,404

# Recursive discovery
feroxbuster -u http://target -w wordlist.txt --depth 3 -o ferox.txt
```

### Parameter Discovery
```bash
# Find hidden parameters
arjun -u http://target/endpoint -oJ params.json
paramspider -d target.com -o params.txt
# Mine from wayback machine
gau target.com | grep '=' | qsreplace 'FUZZ' | sort -u > fuzz_params.txt
waybackurls target.com | grep '=' | sort -u >> fuzz_params.txt
```

### API Endpoint Enumeration
- Check `/api/`, `/v1/`, `/v2/`, `/graphql`, `/swagger.json`, `/openapi.json`.
- Fuzz API paths: `ffuf -u http://target/api/FUZZ -w api-wordlist.txt`
- Look for API docs: Swagger UI, ReDoc, Postman collections.
- Test methods: GET, POST, PUT, DELETE, PATCH, OPTIONS on each endpoint.

### JavaScript Analysis
```bash
# Extract endpoints from JS files
linkfinder -i http://target -o cli               # endpoints from JS
# Find JS files first
gau target.com | grep '\.js$' | sort -u > jsfiles.txt
# Extract secrets/endpoints
cat jsfiles.txt | while read url; do curl -s "$url" | grep -oE '(api|token|key|secret|password)["\s]*[:=]["\s]*[^"]+'; done
```

### Technology Fingerprinting
```bash
whatweb -a 3 -v http://target                     # aggressive fingerprint
# httpx with tech detection
echo http://target | httpx -tech-detect -status-code -title
# Wappalyzer (browser extension or CLI)
wappalyzer http://target
```

---

## Infrastructure Mapping

### DNS Enumeration
```bash
# Zone transfer attempt (often blocked)
dig axfr target.com @ns1.target.com
dnsrecon -d target.com -t axfr

# Standard records
dig target.com ANY +noall +answer
dig target.com MX +short
dig target.com TXT +short                        # SPF, DKIM, DMARC reveal infra
dig target.com NS +short

# Reverse DNS
dnsrecon -r 192.168.1.0/24 -t rvl
```

### Subdomain Enumeration
```bash
# Passive
subfinder -d target.com -all -o subs_passive.txt
amass enum -passive -d target.com -o subs_amass.txt

# Active brute-force (authorized only)
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
dnsenum target.com --enum -f subdomains.txt

# Merge and verify
cat subs_*.txt | sort -u | httpx -silent -o live_subs.txt
```

### VHost Discovery
```bash
# Brute-force virtual hosts
ffuf -u http://TARGET -H 'Host: FUZZ.target.com' -w vhosts.txt -fs <default_size>
gobuster vhost -u http://target.com -w vhosts.txt
```

### CDN Bypass (Direct IP)
- Check historical DNS: `SecurityTrails`, `ViewDNS.info`.
- Look for subdomains not behind CDN (mail, dev, staging).
- Check SPF/TXT records for origin IP leaks.
- `censys search 'services.tls.certificates.leaf.names: target.com'` — find origin.

### Cloud Asset Discovery
- **AWS:** S3 buckets (`http://target.s3.amazonaws.com`), EC2 metadata, CloudFront origins.
- **Azure:** Blob storage (`target.blob.core.windows.net`), App Service defaults.
- **GCP:** Storage buckets, Cloud Run endpoints, Firebase defaults.
- Tool: `cloud_enum -k target -k target.com`

### WAF Identification
```bash
wafw00f http://target                             # identify WAF vendor
# Common WAFs: Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity
# Knowing the WAF helps choose bypass techniques
```

---

## Visual Recon
```bash
# Screenshot live hosts
eyewitness --web -f urls.txt -d /tmp/eyewitness_output
# Or with aquatone
cat urls.txt | aquatone -out /tmp/aquatone_output
```

---

---

## Output-Driven Attack Routing

When recon reveals a service, immediately route to the right attack path.
Full details: `references/recon_to_attack_routing.md`

| Found | Do Next |
|-------|---------|
| WordPress (wp-content, xmlrpc.php) | `wpscan --enumerate u,ap,at,vp` → plugin CVEs → xmlrpc brute |
| Jenkins (X-Jenkins header, /script) | Check Script Console RCE → enumerate jobs → extract creds |
| Kerberos (88) | AS-REP Roast → Kerberoast → LDAP enum |
| SMB (445) | Null session → share enum → EternalBlue check |
| MSSQL (1433) | Default sa creds → xp_cmdshell → linked servers |
| Redis (6379) | Unauth access → dump keys → write webshell |
| MongoDB (27017) | Unauth access → dump databases → extract users |
| Docker API (2375) | Unauth API → list containers → privileged escape |
| K8s API (6443) | Unauth namespace list → service account abuse |
| SNMP (161/UDP) | Community string brute → full device walk |
| SMTP (25) | VRFY/EXPN user enum → open relay check |

---

## Quality Checklist

Before closing recon, verify:
- [ ] **Subdomains** — ran passive (subfinder, crt.sh, amass) + active brute if authorized
- [ ] **Ports** — at minimum top 1000 TCP + top 100 UDP
- [ ] **JavaScript files** — collected and analyzed for endpoints/secrets (LinkFinder, secret grep)
- [ ] **Cloud assets** — checked S3/Azure/GCP bucket patterns, cloud_enum
- [ ] **API endpoints** — checked swagger.json, openapi.json, graphql, api-docs
- [ ] **Wayback/GAU** — mined archived URLs for forgotten endpoints
- [ ] **Technology stack** — fingerprinted (whatweb, httpx, Wappalyzer)
- [ ] **CDN/WAF identified** — wafw00f run, origin IP search attempted
- [ ] **Evidence saved** — all outputs in structured JSON with timestamps

---

## Chain To

Feed recon outputs into subsequent phases:
- **Scanning/Vuln Assessment:** `recon_hosts.json` + `services.json` → nuclei, nikto, nessus
- **Exploitation:** `endpoints.json` + attack routing table → load appropriate exploit skill
- **Password Attacks:** email lists + username patterns → credential spray / brute-force skill
- **Social Engineering:** employee list + email format → phishing skill

---

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| subfinder | No results | Try amass, crt.sh manual query, SecurityTrails API |
| gobuster dir | All 403s | Try different wordlist, add `-x php,html,txt`, check WAF |
| ffuf | Too many results | Use `-fs` to filter by response size, `-fc 403` |
| nmap -sV | Filtered ports | Try `-Pn`, switch to `-sS` SYN scan, try from different source |
| whatweb | Connection reset | Target may block scanners; try `curl -sI` manually |
| DNS zone transfer | Refused | Expected — use subfinder, amass, crt.sh instead |
| amass enum | Timeout/slow | Use `-passive` only, increase timeout, try subfinder first |
| cloud_enum | No buckets found | Try variations: target, target-dev, target-prod, target-backup |

## Technique Chaining Playbooks

### Full External Recon Chain
```
1. Passive OSINT 🟢 (Shodan, crt.sh, Google dorks)
   └── Subdomains found → verify with httpx
2. DNS enumeration 🟡 (subfinder, amass -passive)
   └── Live hosts → feed to port scanner
3. Port scanning 🟡 (nmap -sV -sC top 1000)
   └── Services found → feed to scanning/vuln skill
4. Web content discovery 🔴 (gobuster, ffuf)
   └── Endpoints found → feed to exploitation skill
5. JS analysis 🟢 (linkfinder, secret grep)
   └── API keys/endpoints → feed to exploitation skill
```

### Internal Network Recon (Post-Access)
```
1. OS-native commands 🟢 (ip a, arp -a, ss -tlnp)
2. Ping sweep 🟡 (nmap -sn or bash for loop)
3. Service scan 🟡 (nmap -sV on live hosts)
4. Share enumeration 🟡 (crackmapexec, smbclient)
   └── Accessible shares → feed to collection skill
5. AD enumeration 🔴 (BloodHound, ldapsearch)
   └── DA path found → feed to privilege_escalation skill
```

## Examples
See [examples/nmap-service-scan.md](examples/nmap-service-scan.md) for real nmap service scan output.
See [examples/subdomain-enum.md](examples/subdomain-enum.md) for subdomain enumeration workflow.
See [examples/web-content-discovery.md](examples/web-content-discovery.md) for directory brute-force results.

---

## Deep Dives
Load references when needed:
1. Scope normalization: `references/scope_normalization.md`
2. Rate limits: `references/rate_limits.md`
3. Service mapping: `references/service_mapping.md`
4. Evidence capture: `references/evidence_capture.md`
5. OSINT methodology: `references/osint_methodology.md`
6. Web recon: `references/web_recon.md`
7. Infrastructure mapping: `references/infrastructure_mapping.md`
8. **Advanced recon:** `references/advanced_recon.md` — passive deep dive, JS analysis, API recon, cloud assets, WAF fingerprinting
9. **Recon-to-attack routing:** `references/recon_to_attack_routing.md` — what findings trigger which attack paths
10. **OPSEC:** `references/opsec_recon.md` — noise tiers, scan timing, source IP, rate limit evasion
11. **Failure recovery:** `references/failure_recovery_recon.md` — when standard recon stalls

## MITRE ATT&CK Mappings
- T1589 — Gather Victim Identity Information
- T1590 — Gather Victim Network Information
- T1591 — Gather Victim Org Information
- T1592 — Gather Victim Host Information
- T1593 — Search Open Websites/Domains
- T1594 — Search Victim-Owned Websites
- T1595 — Active Scanning
- T1596 — Search Open Technical Databases

## Evidence Collection
1. `recon_hosts.json` with hosts and ports (parsed from nmap output).
2. `services.json` with service inventory and version hints.
3. `endpoints.json` with URLs, status codes, and titles (from HTTP discovery).
4. `evidence.json` with raw outputs, command lines, and timestamps.
5. `findings.json` with recon observations.
6. `subdomains.txt` with enumerated subdomains.
7. `params.json` with discovered parameters.

## Evidence Consolidation
1. Use `parse_nmap_grepable.py` to convert `-oG` output into `recon_hosts.json`.
2. Use `summarize_httpx.py` from `skills/http/scripts/` when HTTP discovery is used.

## Success Criteria
- Active hosts and services identified with evidence.
- Subdomains and web surface area mapped.
- Technology stack fingerprinted.
- Recon outputs captured safely and consistently.
- Attack surface documented for exploitation phase.
