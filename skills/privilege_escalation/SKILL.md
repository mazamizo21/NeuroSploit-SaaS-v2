# Privilege Escalation Skill

## Overview
Escalating privileges from initial access (usually low-privileged user) to higher privileges (root, admin, domain admin) to achieve full system control.

## Methodology

### 1. System Enumeration
- OS and kernel version
- Installed software and versions
- Running services and configurations
- Network configuration and shares
- SUID/SGID binaries
- Cron jobs and scheduled tasks
- Weak permissions on files/directories
- User accounts and groups

### 2. Linux Privilege Escalation
- Check for kernel exploits (CVEs)
- Exploit SUID binaries
- Exploit weak file permissions
- Exploit writable PATH directories
- Exploit LD_PRELOAD and shared library hijacking
- Exploit cron jobs
- Exploit NFS root squashing misconfig
- Exploit Docker container escape

### 3. Windows Privilege Escalation
- Check for unquoted service paths
- Exploit weak service permissions
- Exploit alwaysinstall elevated
- Exploit stored credentials (cached, LSA, etc.)
- Exploit registry autoruns
- Exploit kernel exploits
- Exploit token impersonation
- Exploit DLL hijacking

### 4. Database Privilege Escalation
- MySQL: file write, UDF exploitation
- PostgreSQL: COPY command, file operations
- SQL Server: xp_cmdshell, CLR integration
- Oracle: Java stored procedures

### 5. Automated Tools
- LinPEAS: Linux Privilege Escalation Awesome Script
- WinPEAS: Windows Privilege Escalation Awesome Script
- Linux Exploit Suggester: Suggest kernel exploits
- Sherlock: PowerShell vulnerability scanner

### 6. Manual Techniques
- PATH hijacking
- LD_PRELOAD injection
- Wildcard injection
- Environment variable injection
- Shared library injection

## MITRE ATT&CK Mappings
- T1068 - Exploitation for Privilege Escalation
- T1548 - Abuse Elevation Control Mechanism
- T1053 - Scheduled Task/Job
- T1069 - Permission Groups Discovery
- T1007 - System Service Discovery

## Tools Available
- linpeas: Linux Privilege Escalation Awesome Script
- winpeas: Windows Privilege Escalation Awesome Script
- linux-exploit-suggester: Linux kernel exploit suggestion tool
- sherlock: PowerShell vulnerability scanner
- gtfobins: GTFOBins - Unix binaries for privilege escalation
- lse: Linux Smart Enumeration
- pspy: Monitor processes without root

## Evidence Collection
1. System enumeration results
2. Exploitation commands and output
3. Root access proof (whoami, id)
4. Sensitive files extracted (/etc/shadow, SAM, etc.)
5. Screenshot of elevated privileges
6. Configuration files with vulnerabilities

## Success Criteria
- Initial access confirmed
- System enumeration complete
- Privilege escalation method identified
- Higher privileges achieved (root/admin)
- Sensitive data extracted if possible
- Persistence established if applicable
- All evidence documented
