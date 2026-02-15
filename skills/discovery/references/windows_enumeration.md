# Windows Post-Access Enumeration Checklist

## System Identification
```cmd
whoami                                  :: Current user
whoami /all                             :: User SID, groups, privileges (critical!)
hostname                                :: System hostname
systeminfo                              :: Full system info — OS, hotfixes, domain, NICs
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
ver                                     :: OS version string
echo %USERDOMAIN%                       :: Domain name
echo %LOGONSERVER%                      :: Authenticating domain controller
echo %COMPUTERNAME%                     :: Computer name
echo %PROCESSOR_ARCHITECTURE%           :: Architecture (AMD64, x86)
set                                     :: All environment variables
```

### PowerShell System Info
```powershell
[Environment]::UserName                 # Username
[Environment]::MachineName              # Hostname
[Environment]::OSVersion                # OS version
$PSVersionTable                         # PowerShell version
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber, CsDomainRole
(Get-WmiObject Win32_OperatingSystem).Caption
Get-HotFix | Select-Object HotFixID, InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 20
```

## User & Group Enumeration
```cmd
net user                                :: Local users
net user <username>                     :: Details for specific user
net localgroup                          :: Local groups
net localgroup administrators           :: Local admin members
net localgroup "Remote Desktop Users"   :: RDP access
net localgroup "Remote Management Users" :: WinRM access
net user /domain                        :: Domain users
net group /domain                       :: Domain groups
net group "Domain Admins" /domain       :: Domain admin members
net group "Enterprise Admins" /domain   :: Enterprise admin members
net group "Domain Controllers" /domain  :: Domain controllers
net group "Schema Admins" /domain       :: Schema admin members
net accounts                            :: Local password policy
net accounts /domain                    :: Domain password policy
```

### PowerShell User Enumeration
```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
Get-LocalGroup | Select-Object Name
Get-LocalGroupMember -Group "Administrators"
Get-LocalGroupMember -Group "Remote Desktop Users"

# Domain (requires RSAT or AD module)
Get-ADUser -Filter * -Properties LastLogonDate, Enabled, MemberOf | Select-Object Name, Enabled, LastLogonDate
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName  # Kerberoastable
```

## Network Configuration
```cmd
ipconfig /all                           :: Full network config with DNS
route print                             :: Routing table
arp -a                                  :: ARP cache
netstat -ano                            :: All connections with PIDs
netstat -anob                           :: Connections with process names (admin)
nbtstat -n                              :: Local NetBIOS names
nbtstat -A <target>                     :: Remote NetBIOS names
net config workstation                  :: Workstation config (domain, DNS)
nslookup -type=SRV _ldap._tcp.dc._msdcs.%USERDNSDOMAIN%  :: Find DCs
```

### PowerShell Network
```powershell
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength
Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias
Get-NetNeighbor | Where-Object {$_.State -ne "Unreachable"} | Select-Object IPAddress, LinkLayerAddress
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress, LocalPort, OwningProcess
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
Resolve-DnsName -Name _ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN -Type SRV  # Find DCs
Test-NetConnection -ComputerName <target> -Port 445  # Test specific port
```

## Process & Service Enumeration
```cmd
tasklist                                :: Running processes
tasklist /svc                           :: Processes mapped to services
tasklist /v                             :: Verbose with status and memory
tasklist /fi "USERNAME ne NT AUTHORITY\SYSTEM" /fi "STATUS eq running"  :: Non-SYSTEM processes
sc query                                :: Running services
sc query state= all                     :: All services
sc qc <service>                         :: Service configuration details
wmic service list config                :: Service details via WMI
wmic process list brief                 :: Process list via WMI
```

### PowerShell Services
```powershell
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, StartType
Get-Process | Select-Object Name, Id, Path | Sort-Object Name
Get-WmiObject win32_service | Select-Object Name, PathName, StartMode, State | Where-Object {$_.State -eq "Running"}
# Services with unquoted paths (privesc)
Get-WmiObject win32_service | Where-Object {$_.PathName -notlike "C:\Windows\*" -and $_.PathName -notlike '"*'} | Select-Object Name, PathName, StartMode
```

## Installed Software
```cmd
wmic product get name,version           :: Installed products (slow, queries MSI)
wmic qfe list brief                     :: Installed hotfixes
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName DisplayVersion"
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName DisplayVersion"
```

### PowerShell Software
```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
```

## Scheduled Tasks & Autorun
```cmd
schtasks /query /fo LIST /v             :: All scheduled tasks (verbose)
schtasks /query /fo TABLE               :: Scheduled tasks (table format)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
wmic startup list full                  :: Startup programs
```

### PowerShell Scheduled Tasks
```powershell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State
Get-ScheduledTask | ForEach-Object { [pscustomobject]@{
    Name = $_.TaskName
    Action = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments })
    Trigger = ($_.Triggers | ForEach-Object { $_.ToString() })
}} | Format-Table -AutoSize
```

## Firewall & Security
```cmd
netsh advfirewall show allprofiles      :: Firewall status all profiles
netsh advfirewall firewall show rule name=all  :: All firewall rules
netsh firewall show state               :: Legacy firewall state
sc query windefend                      :: Windows Defender service
```

### PowerShell Firewall & Security
```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'} |
    Select-Object DisplayName, Action, LocalPort -First 30
Get-MpComputerStatus                    # Defender status
Get-MpPreference                        # Defender configuration
Get-MpThreatDetection                   # Recent detections
```

## Security Tools Detection
```cmd
:: AV/EDR detection
tasklist /svc | findstr /i "MsMpEng falcon carbon sentinel cylance sophos symantec mcafee eset kaspersky trend"
sc query windefend
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "antivirus security endpoint protection"
```

### PowerShell Security Tools
```powershell
# Check for common EDR/AV processes
$edrProcesses = @("MsMpEng","csfalconservice","cb","CylanceSvc","SentinelAgent","SentinelServiceHost","SophosClean","savservice","ekrn","avp","mfetp","TmListen","ds_agent","xagt")
Get-Process | Where-Object { $edrProcesses -contains $_.Name } | Select-Object Name, Id, Path
# AMSI bypass check
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')  # Check if AMSI is loaded
```

## Shares & Drives
```cmd
net share                               :: Local shares
net use                                 :: Mapped network drives
net view                                :: Visible network hosts
net view /domain                        :: Visible domains
net view \\<target>                     :: Shares on specific host
dir \\<target>\C$ 2>nul                 :: Test admin share access
```

## Automated Enumeration
```powershell
# WinPEAS
.\winPEASx64.exe
.\winPEASx64.exe quiet systeminfo userinfo

# Seatbelt
.\Seatbelt.exe -group=all
.\Seatbelt.exe AntiVirus AppLocker CloudCredentials CredGuard DNSCache DotNet InterestingProcesses LocalGroups LocalUsers LogonSessions MappedDrives NetworkShares
.\Seatbelt.exe -group=all -outputfile=C:\temp\seatbelt.txt

# PowerUp (privilege escalation)
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```
