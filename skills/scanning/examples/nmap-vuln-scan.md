# Nmap Vulnerability Scan Example

## Command
```bash
$ nmap --script vuln,smb-vuln* -sV -p 445,3389,80 10.10.10.40
```

## Output
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-15 15:10 EST
Nmap scan report for 10.10.10.40
Host is up (0.031s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 7.5
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-vuln-cve2015-1635:
|   VULNERABLE:
|   Remote Code Execution vulnerability in HTTP.sys (MS15-034)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-1635
|       A remote code execution vulnerability exists in HTTP.sys when the
|       component improperly parses specially crafted HTTP requests.
|
|     Disclosure date: 2015-04-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635
445/tcp  open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in SMBv1.
|
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|_    References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-vuln-ms12-020:
|   VULNERABLE:
|   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0002
|_    References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 42.18 seconds
```

## Key Findings
| CVE | Service | Severity | Exploitable |
|-----|---------|----------|-------------|
| MS17-010 (EternalBlue) | SMB/445 | **CRITICAL** | Yes — reliable RCE to SYSTEM |
| MS15-034 (HTTP.sys) | HTTP/80 | **CRITICAL** | Yes — RCE or DoS |
| MS08-067 | SMB/445 | **HIGH** | Likely — older but proven exploit |
| MS12-020 (BlueKeep) | RDP/3389 | **HIGH** | DoS confirmed, RCE possible |

## Next Steps
→ **exploitation skill**: MS17-010 EternalBlue → SYSTEM shell (highest reliability)
→ **exploitation skill**: MS15-034 → RCE via crafted HTTP Range header
