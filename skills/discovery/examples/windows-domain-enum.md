# Windows Domain Enumeration

## Scenario
Compromised domain user `jsmith` on MEGACORP.LOCAL.

## Phase 1: System Context
```cmd
C:\> whoami /all
USER INFORMATION
----------------
User Name          SID
================== =============================================
megacorp\jsmith    S-1-5-21-3456789012-1234567890-9876543210-1108

GROUP INFORMATION
-----------------
Group Name                                 Type             SID
========================================== ================ ============
MEGACORP\Domain Users                      Group            S-1-5-21-...
MEGACORP\IT Helpdesk                       Group            S-1-5-21-...
BUILTIN\Users                              Alias            S-1-5-32-545

PRIVILEGES INFORMATION
----------------------
SeChangeNotifyPrivilege        Bypass traverse checking      Enabled

C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Hotfix"
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
Hotfix(s):                 8 Hotfix(s) Installed.
```

## Phase 2: Domain Information
```cmd
C:\> echo %USERDOMAIN% / %LOGONSERVER%
MEGACORP / \\DC01

C:\> net group "Domain Admins" /domain
Group name     Domain Admins
Members
----------------------------------------------------------------
Administrator            svc_admin                t.johnson

C:\> net group "Domain Controllers" /domain
Members
----------------------------------------------------------------
DC01$                    DC02$

C:\> nltest /domain_trusts
List of domain trusts:
    0: MEGACORP megacorp.local (NT 5) (Direct Outbound) (Direct Inbound)
    1: PARTNER partner.corp (NT 5) (Direct Outbound) (Forest: 2)
The command completed successfully.
```

## Phase 3: Network Mapping
```cmd
C:\> ipconfig /all | findstr /C:"IPv4" /C:"DNS Servers" /C:"Default Gateway"
   IPv4 Address. . . . . . . . . . . : 10.10.10.55
   Default Gateway . . . . . . . . . : 10.10.10.1
   DNS Servers . . . . . . . . . . . : 10.10.10.100
                                        10.10.10.101

C:\> arp -a
  Internet Address      Physical Address      Type
  10.10.10.1            00-0c-29-aa-bb-cc     dynamic
  10.10.10.50           00-0c-29-dd-ee-ff     dynamic
  10.10.10.80           00-0c-29-11-22-33     dynamic
  10.10.10.100          00-0c-29-44-55-66     dynamic   <-- DC01
  10.10.10.101          00-0c-29-77-88-99     dynamic   <-- DC02
```

## Key Findings
| Finding | Impact |
|---------|--------|
| 3 Domain Admins: Administrator, svc_admin, t.johnson | High-value targets |
| Forest trust to PARTNER.CORP | Cross-domain attack path |
| 2 Domain Controllers (DC01, DC02) | Target for DCSync |
| jsmith in IT Helpdesk | May have password reset/service desk access |
| 5 hosts on network (ARP table) | Internal attack surface |

## Next Steps
→ **credential_access skill**: Kerberoast svc_admin if SPN set
→ **lateral_movement skill**: Enumerate shares on 10.10.10.50, .80
→ **discovery skill**: BloodHound collection for full AD graph
