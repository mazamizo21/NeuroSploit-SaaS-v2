---
name: vulnerability-scanning
description: Systematic vulnerability identification using automated scanners, manual validation, and CVE correlation. Service-aware scanning with false positive reduction.
---

# Vulnerability Scanning Skill

## Overview
Systematic vulnerability identification using automated scanners, manual validation,
and CVE correlation. Takes recon output (ports, services, tech stack) and finds
exploitable weaknesses. Key principle: **scan smart, not loud**.

## Scope Rules
1. Only scan explicitly in-scope services discovered during recon.
2. External targets: conservative rate limits, no destructive templates.
3. Validate findings before reporting — reduce false positives.
4. Cross-reference multiple scanners for confidence.

---

## Scanning Decision Tree

```
What services were found in recon?
├── Web (80/443/8080/8443)
│   ├── nuclei -severity critical,high,medium (first pass)
│   ├── nikto -h <url> (web server misconfig)
│   ├── whatweb -a 3 (if not done in recon)
│   ├── Check CMS → wpscan / droopescan / joomscan
│   ├── sqlmap on discovered parameters (GET/POST)
│   ├── ffuf for parameter fuzzing
│   └── SSL/TLS → testssl.sh or sslyze
├── SMB (445/139)
│   ├── nmap --script smb-vuln* (EternalBlue, etc.)
│   ├── crackmapexec smb --gen-relay-list (signing check)
│   ├── enum4linux-ng -A <target>
│   └── smbmap -H <target> (share permissions)
├── SSH (22)
│   ├── nmap --script ssh-auth-methods,ssh2-enum-algos
│   ├── ssh-audit <target> (algo weakness, version vulns)
│   └── Check version against CVE database
├── RDP (3389)
│   ├── nmap --script rdp-vuln-ms12-020,rdp-ntlm-info
│   └── rdp-sec-check <target>
├── Database (1433/3306/5432/27017)
│   ├── nmap --script ms-sql-info,mysql-info,pgsql-info
│   ├── Default credential check
│   └── Version → CVE correlation
├── Mail (25/110/143/465/587/993/995)
│   ├── nmap --script smtp-commands,smtp-vuln*
│   └── smtp-user-enum for user enumeration
└── Other services
    ├── nmap --script default,vuln -sV -p <port>
    └── searchsploit <service> <version>
```

---

## Scanner Priority (run in order)

### Tier 1: Quick Wins (< 5 min)
1. `nmap --script vuln -sV -p <open_ports> <target>` — NSE vuln scripts
2. `nuclei -u <url> -severity critical,high -rate-limit 50` — known CVEs
3. `searchsploit <service> <version>` — exploit-db matches

### Tier 2: Deep Scan (5-30 min)
4. `nikto -h <url> -Tuning x6` — web server vulns + misconfigs
5. `nuclei -u <url> -severity medium,low -tags cve,misconfig`
6. `sqlmap -u "<url>?param=test" --batch --level 3 --risk 2` — SQLi
7. `testssl.sh <host>:443` — SSL/TLS analysis
8. `nmap --script smb-vuln*,rdp-vuln* -p 445,3389 <target>` — Windows vulns

### Tier 3: Targeted (30+ min, based on findings)
9. `wpscan --url <url> --enumerate vp,vt,u` — WordPress deep scan
10. `ffuf -u <url>/FUZZ -w params.txt -mc all -fc 404` — parameter discovery
11. `nuclei -u <url> -tags xss,ssrf,lfi,rfi,rce` — injection templates
12. `hydra -L users.txt -P passwords.txt <target> <service>` — brute force

---

## Nmap NSE Script Categories

| Category | Scripts | Use When |
|----------|---------|----------|
| **SMB** | `smb-vuln-ms17-010` (EternalBlue), `smb-vuln-ms08-067`, `smb-enum-shares`, `smb-os-discovery` | Port 445 open |
| **RDP** | `rdp-vuln-ms12-020` (BlueKeep), `rdp-ntlm-info`, `rdp-enum-encryption` | Port 3389 open |
| **HTTP** | `http-vuln*`, `http-enum`, `http-headers`, `http-methods`, `http-shellshock` | Port 80/443 open |
| **SSH** | `ssh-auth-methods`, `ssh2-enum-algos`, `ssh-hostkey` | Port 22 open |
| **SQL** | `ms-sql-info`, `ms-sql-brute`, `mysql-info`, `mysql-enum` | DB ports open |
| **SMTP** | `smtp-commands`, `smtp-enum-users`, `smtp-vuln-cve2010-4344` | Port 25/587 open |
| **FTP** | `ftp-anon`, `ftp-vsftpd-backdoor`, `ftp-vuln-cve2010-4221` | Port 21 open |

---

## Nuclei Template Strategy

```bash
# Phase 1: Critical CVEs only (fast, low noise)
nuclei -u http://target -severity critical,high -rate-limit 100 -o nuclei_crit.json -jsonl

# Phase 2: Misconfigurations + info disclosure
nuclei -u http://target -tags misconfig,exposure,token -o nuclei_misconfig.json -jsonl

# Phase 3: Injection testing (slower, more aggressive)
nuclei -u http://target -tags sqli,xss,ssrf,lfi,rce -o nuclei_inject.json -jsonl

# Phase 4: Technology-specific
nuclei -u http://target -tags iis       # IIS-specific vulns
nuclei -u http://target -tags apache    # Apache-specific
nuclei -u http://target -tags nginx     # Nginx-specific
nuclei -u http://target -tags wordpress # WordPress vulns

# Always use:
# -rate-limit 50-100 (external), unlimited (lab)
# -jsonl for machine-parseable output
# -severity to control noise level
# -o <file> to save results
```

---

## SQLMap Strategy

```bash
# Basic test on discovered parameter
sqlmap -u "http://target/page?id=1" --batch --level 3 --risk 2

# POST parameter
sqlmap -u "http://target/login" --data "user=admin&pass=test" --batch

# Cookie-based injection
sqlmap -u "http://target/dashboard" --cookie "session=abc123" --batch

# If injectable, escalate:
sqlmap -u "..." --dbs                    # list databases
sqlmap -u "..." -D dbname --tables       # list tables
sqlmap -u "..." -D dbname -T users --dump # dump users table
sqlmap -u "..." --os-shell               # OS command execution
sqlmap -u "..." --file-read="/etc/passwd" # file read

# Tamper scripts for WAF bypass:
sqlmap -u "..." --tamper=space2comment,between,randomcase
```

---

## False Positive Reduction

### Validation Steps (MANDATORY before reporting)
1. **Reproduce manually** — `curl` the exact URL/payload the scanner flagged
2. **Check response** — Does the response actually confirm the vuln?
3. **Version verify** — Is the detected version actually vulnerable? (check patch level)
4. **Cross-validate** — Run a second scanner or manual test
5. **Context check** — Is this a honeypot/decoy? Is the service actually reachable?

### Common False Positives
| Scanner | False Positive | How to Verify |
|---------|---------------|---------------|
| Nuclei | "Exposed .git" | `curl -s target/.git/HEAD` — must return `ref:` |
| Nuclei | "Open redirect" | Actually follow the redirect, check destination |
| Nikto | "Server version" | Banner != actual version (could be spoofed) |
| Nmap | "vuln-ms17-010" | May report "likely vulnerable" without proof |
| SQLMap | "Injectable" | Check if actual data extraction works |

### Severity Calibration
- **Critical**: RCE, auth bypass, SQLi with data access, pre-auth vulns
- **High**: SQLi (blind), SSRF, LFI with sensitive file read, privesc vulns
- **Medium**: XSS (stored), IDOR, info disclosure (credentials/PII)
- **Low**: XSS (reflected), missing headers, verbose errors, version disclosure
- **Info**: Technology detected, default pages, DNS records

---

## Evidence Collection

### Required per Finding
1. **Scanner output** — raw nuclei/nmap/nikto output
2. **Manual validation** — curl command + response proving the vuln
3. **Impact assessment** — what can an attacker do with this?
4. **Remediation** — specific fix recommendation

### Output Files
- `vulns.json` — validated vulnerabilities with evidence
- `scan_findings.json` — parsed scanner output (via `parse_nuclei_json.py`)
- `findings.json` — final findings ready for reporting
- `evidence.json` — raw scanner outputs and command lines

---

## Windows-Specific Scanning

### IIS Checks
```bash
# IIS shortname scanner (8.3 filename disclosure)
nmap --script http-iis-short-name-brute -p 80 <target>

# IIS WebDAV
nmap --script http-webdav-scan -p 80 <target>
curl -X OPTIONS http://target/ -v  # check allowed methods

# ASP.NET debugging
curl http://target/trace.axd
curl http://target/elmah.axd
```

### SMB/Windows Vuln Checks
```bash
# EternalBlue (MS17-010)
nmap --script smb-vuln-ms17-010 -p 445 <target>

# PrintNightmare
rpcdump.py @<target> | grep MS-RPRN

# ZeroLogon (if DC)
nmap --script smb-vuln-ms08-067 -p 445 <target>

# SMB signing (relay attack potential)
crackmapexec smb <target> --gen-relay-list relay.txt
nmap --script smb2-security-mode -p 445 <target>
```

## OPSEC Ratings Per Technique

| Technique | OPSEC | Notes |
|-----------|-------|-------|
| searchsploit (local) | 🟢 Quiet | Offline database lookup, zero network traffic |
| nuclei -severity critical | 🟡 Moderate | HTTP requests to target, rate-limitable |
| nmap --script vuln | 🟡 Moderate | Active probes, generates logs on target |
| nikto | 🟡 Moderate | Noisy web scanner, many requests |
| sqlmap --batch | 🔴 Loud | Aggressive parameter testing, WAF alerts |
| nuclei (injection templates) | 🔴 Loud | Active exploitation attempts, WAF/IDS triggers |
| hydra/medusa brute force | 🔴 Loud | Account lockout risk, heavy logging |

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| nuclei | Rate limited / WAF blocked | Reduce `-rate-limit` to 10, use `-proxy`, rotate User-Agent |
| nuclei | No results | Try broader templates: `-tags cve,misconfig`, check URL is correct |
| nmap NSE | Scripts timeout | Increase `--script-timeout`, reduce parallelism with `--min-parallelism 1` |
| nikto | Connection refused | Verify port/SSL, try `-ssl` flag, check if WAF is blocking |
| sqlmap | No injectable params | Try `--level 5 --risk 3`, test cookies with `--cookie`, try POST params |
| sqlmap | WAF blocking | Use `--tamper=space2comment,between,randomcase`, add `--random-agent` |
| testssl | Connection timeout | Check port, try `--starttls` for non-standard ports |
| wpscan | API token needed | Register at wpscan.com for free API token, or use `--enumerate` without API |

## Technique Chaining Playbooks

### Web Service Full Assessment
```
1. nuclei -severity critical,high (quick CVE check) 🟢
   └── Found CVE? → exploitation skill
2. nikto -Tuning x6 (web misconfig) 🟡
3. nuclei -tags misconfig,exposure (info disclosure) 🟡
4. testssl.sh (SSL/TLS weaknesses) 🟢
5. sqlmap on discovered params (injection) 🔴
   └── Found SQLi? → exploitation skill (data extraction)
6. nuclei -tags xss,ssrf,lfi (injection templates) 🔴
```

### Windows Network Assessment
```
1. nmap --script smb-vuln* (EternalBlue, etc.) 🟡
   └── Found MS17-010? → exploitation skill
2. crackmapexec smb --gen-relay-list (signing check) 🟢
   └── No signing? → credential_access skill (NTLM relay)
3. nmap --script rdp-vuln* (BlueKeep) 🟡
4. enum4linux-ng -A (full SMB enum) 🟡
   └── Found shares? → collection skill
```

## Examples
See [examples/nuclei-web-scan.md](examples/nuclei-web-scan.md) for real nuclei output.
See [examples/nmap-vuln-scan.md](examples/nmap-vuln-scan.md) for nmap NSE vuln scan output.
See [examples/sqlmap-detection.md](examples/sqlmap-detection.md) for sqlmap injection detection.

---

## MITRE ATT&CK Mappings
- T1595 — Active Scanning (port scanning, vuln scanning)
- T1595.001 — Scanning IP Blocks
- T1595.002 — Vulnerability Scanning
- T1190 — Exploit Public-Facing Application
- T1046 — Network Service Discovery
- T1592 — Gather Victim Host Information
- T1018 — Remote System Discovery
