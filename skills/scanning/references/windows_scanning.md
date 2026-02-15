# Windows-Specific Scanning

## Windows Service Detection Priority
When target is identified as Windows (IIS, SMB, RDP open):

### 1. SMB Vulnerability Scan (Critical — do first)
```bash
# EternalBlue (MS17-010) — most impactful Windows vuln
nmap --script smb-vuln-ms17-010 -p 445 target

# Full SMB vuln sweep
nmap --script "smb-vuln*" -p 445 target

# SMB signing check (relay attacks possible if disabled)
nmap --script smb2-security-mode -p 445 target
# Look for: "Message signing enabled but not required" = VULNERABLE

# SMB share enumeration
smbmap -H target
smbmap -H target -u null  # null session
crackmapexec smb target --shares
```

### 2. RDP Scanning
```bash
# BlueKeep (CVE-2019-0708)
nmap --script rdp-vuln-ms12-020 -p 3389 target

# RDP NLA check
nmap --script rdp-ntlm-info -p 3389 target
# Extracts: domain name, computer name, DNS, OS version

# RDP encryption check
nmap --script rdp-enum-encryption -p 3389 target
```

### 3. IIS-Specific Scanning
```bash
# IIS short name brute force (8.3 filename disclosure)
nmap --script http-iis-short-name-brute -p 80,443 target
# Java tool: java -jar IIS_shortname_Scanner.jar http://target/

# WebDAV check
nmap --script http-webdav-scan -p 80,443 target
curl -X OPTIONS http://target/ -v 2>&1 | grep -i "allow\|dav"

# ASP.NET debugging endpoints
curl -s http://target/trace.axd
curl -s http://target/elmah.axd
curl -s http://target/aspnet_client/

# IIS tilde enumeration
# If /~a returns different response than /~z, 8.3 names are enabled

# web.config disclosure
curl -s http://target/web.config
curl -s http://target/web.config.bak
curl -s http://target/web.config.old
curl -s http://target/web.config.txt
```

### 4. WinRM/PowerShell Remoting
```bash
# Check if WinRM is open
nmap -p 5985,5986,47001 target

# Test with crackmapexec (no creds needed to check)
crackmapexec winrm target

# If you have creds:
crackmapexec winrm target -u user -p pass -x "whoami"
evil-winrm -i target -u user -p pass
```

### 5. MSRPC Enumeration
```bash
# RPC endpoint mapper
rpcdump.py @target

# Interesting RPC interfaces:
# MS-RPRN (PrintNightmare) — spoolss
# MS-EFSR (PetitPotam) — efsrpc
# MS-DFSNM (DFSCoerce) — netdfs
rpcdump.py @target | grep -E "RPRN|EFSR|DFSNM"
```

### 6. LDAP (if port 389/636 open — Domain Controller)
```bash
nmap --script ldap-rootdse -p 389 target
ldapsearch -x -H ldap://target -s base namingContexts
```

## Windows Version → CVE Quick Reference
| Build/Version | Key CVEs |
|---------------|----------|
| Windows 7 / Server 2008 R2 | MS17-010, CVE-2019-0708 (BlueKeep) |
| Windows 8.1 / Server 2012 R2 | MS17-010, MS14-068 (Kerberos) |
| Windows 10 1903-1909 | CVE-2020-0796 (SMBGhost) |
| Windows 10 2004+ | CVE-2020-1472 (ZeroLogon if DC) |
| Windows 11 | Generally well-patched, focus on misconfigs |
| Server 2016 | MS17-010, PrintNightmare |
| Server 2019 | PrintNightmare, PetitPotam |
| Server 2022 | Focus on misconfigs, not CVEs |

## Credential Spraying (After Initial Scan)
```bash
# If you find usernames from RDP NTLM info or SMB:
crackmapexec smb target -u users.txt -p 'Password123!' --no-brute
crackmapexec smb target -u users.txt -p 'Season2026!' --no-brute

# Common Windows default passwords:
# Password1, Welcome1, Company2026!, Season+Year, Qwerty123
```
