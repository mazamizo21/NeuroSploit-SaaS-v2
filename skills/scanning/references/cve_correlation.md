# CVE Correlation Guide

## Workflow
1. Extract service name + exact version from nmap/banner grab
2. Search CVE databases for matches
3. Validate applicability (OS, config, patch level)
4. Rate exploitability (public PoC? Metasploit module? Active exploitation?)

## Search Sources (Priority Order)
```bash
# 1. Local exploit-db (fastest)
searchsploit <service> <version>
searchsploit -j <service> <version>  # JSON output

# 2. Nmap vuln scripts (automated)
nmap --script vulners -sV -p <port> <target>

# 3. Nuclei CVE templates
nuclei -u <url> -tags cve -severity critical,high

# 4. Online databases
# - https://www.cvedetails.com/
# - https://nvd.nist.gov/
# - https://exploit-db.com/
# - https://github.com/advisories
```

## Version Extraction Patterns
| Service | Version Source | Example |
|---------|--------------|---------|
| Apache | Server header | `Apache/2.4.49` → CVE-2021-41773 |
| IIS | Server header | `Microsoft-IIS/10.0` → check build number |
| OpenSSH | Banner | `SSH-2.0-OpenSSH_8.2p1` → CVE-2021-41617 |
| nginx | Server header | `nginx/1.18.0` → CVE-2021-23017 |
| MySQL | Banner/nmap | `5.7.34-0ubuntu0.18.04.1` |
| PostgreSQL | Banner | `PostgreSQL 12.7` |
| SMB | nmap os-discovery | `Windows 10 Build 19041` |

## High-Value CVEs by Service
### IIS
- CVE-2017-7269 (IIS 6.0 WebDAV RCE) — `nmap --script http-iis-webdav-vuln`
- CVE-2021-31166 (HTTP Protocol Stack RCE) — affects IIS on Win10/Server

### SMB
- MS17-010 EternalBlue — `nmap --script smb-vuln-ms17-010`
- MS08-067 — `nmap --script smb-vuln-ms08-067`
- CVE-2020-0796 SMBGhost — check SMBv3.1.1 compression

### SSH
- CVE-2018-15473 (user enumeration) — OpenSSH < 7.7
- CVE-2016-0777 (roaming buffer overflow) — OpenSSH 5.x-7.1

### RDP
- CVE-2019-0708 BlueKeep — `nmap --script rdp-vuln-ms12-020`
- CVE-2012-0002 — MS12-020 DoS

### Apache
- CVE-2021-41773 (path traversal) — Apache 2.4.49-2.4.50
- CVE-2021-42013 (RCE) — Apache 2.4.49-2.4.50
- CVE-2019-0211 (privesc) — Apache 2.4.17-2.4.38

## Patch Detection
- **Windows:** Check build number, not just major version
- **Linux:** Check distro-specific backports (`dpkg -l | grep <package>`)
- **Web servers:** Check minor/patch version, not just major
- **When in doubt:** Mark as "potentially vulnerable, needs manual verification"

## Confidence Levels
- **Confirmed:** Exploit succeeded or definitive version match with no backport
- **Likely:** Version matches CVE range, no patch evidence found
- **Possible:** Version is close but could be patched/backported
- **False Positive:** Version doesn't match, or service behavior contradicts
