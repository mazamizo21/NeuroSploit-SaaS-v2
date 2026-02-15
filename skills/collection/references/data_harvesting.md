# Data Harvesting Reference — File Discovery Patterns & High-Value Targets

## Linux File Discovery

### Quick Wins (Run First)

```bash
# History files — often contain passwords typed in commands
cat ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history 2>/dev/null

# Environment variables — API keys, tokens, passwords
env | grep -iE "pass|key|token|secret|api|cred"
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|key|token"

# SSH material
ls -la ~/.ssh/
cat ~/.ssh/id_rsa ~/.ssh/id_ed25519 ~/.ssh/config ~/.ssh/known_hosts 2>/dev/null

# Cloud credentials
cat ~/.aws/credentials ~/.aws/config 2>/dev/null
cat ~/.azure/accessTokens.json 2>/dev/null
cat ~/.config/gcloud/credentials.db 2>/dev/null
cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null
```

### Broad File Discovery

```bash
# Databases & backups
find / -name "*.sql" -o -name "*.sqlite" -o -name "*.db" -o -name "*.mdb" 2>/dev/null
find / -name "*.bak" -o -name "*.backup" -o -name "*.dump" -o -name "*.old" 2>/dev/null

# Password databases
find / -name "*.kdbx" -o -name "*.kdb" -o -name "*.psafe3" 2>/dev/null

# Certificates & keys
find / -name "*.pem" -o -name "*.key" -o -name "*.pfx" -o -name "*.p12" -o -name "*.crt" 2>/dev/null
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null

# Config files with credentials
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" 2>/dev/null | head -100
grep -rl "password" /etc/ /opt/ /var/www/ 2>/dev/null

# Web application configs
find /var/www/ /opt/ /srv/ -name "wp-config.php" -o -name ".env" -o -name "settings.py" \
  -o -name "database.yml" -o -name "config.php" -o -name "web.config" 2>/dev/null
```

### Targeted Grep Patterns

```bash
# Search for passwords in config files
grep -rni "password\s*=" /etc/ /opt/ /var/www/ --include="*.conf" --include="*.php" \
  --include="*.py" --include="*.yml" --include="*.xml" --include="*.ini" 2>/dev/null

# Connection strings
grep -rni "jdbc:\|mysql://\|postgres://\|mongodb://\|redis://" /opt/ /var/www/ /etc/ 2>/dev/null

# API keys and tokens
grep -rni "api_key\|apikey\|api-key\|secret_key\|access_key\|AKIA[0-9A-Z]" \
  /home/ /opt/ /var/www/ /root/ 2>/dev/null

# Private keys embedded in files
grep -rl "BEGIN.*PRIVATE KEY" /etc/ /home/ /opt/ /root/ 2>/dev/null
```

## Windows File Discovery

### Quick Wins

```powershell
# Interesting files in user directories
dir /s /b C:\Users\*.kdbx C:\Users\*.key C:\Users\*.pem C:\Users\*.pfx 2>nul
dir /s /b C:\Users\*.rdp C:\Users\*.vnc C:\Users\*.pcf 2>nul

# Unattend files (plaintext/base64 creds)
dir /s /b C:\unattend.xml C:\Autounattend.xml 2>nul
type C:\Windows\Panther\unattend.xml 2>nul
type C:\Windows\Panther\Autounattend.xml 2>nul
type C:\Windows\System32\Sysprep\unattend.xml 2>nul

# IIS and web configs
dir /s /b C:\inetpub\*.config 2>nul
findstr /si "connectionString password" C:\inetpub\*.config 2>nul

# PowerShell history (goldmine)
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-Content (Get-PSReadLineOption).HistorySavePath
```

### Registry Mining

```powershell
# Autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultUserName 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword 2>nul

# Saved PuTTY sessions (proxy passwords)
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# Saved RDP connections
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s

# SNMP community strings
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"

# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server" /v Password
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password
```

## High-Value Targets by Service

| Service        | Files / Paths                                               |
| -------------- | ----------------------------------------------------------- |
| Apache         | /etc/apache2/sites-enabled/*.conf, .htpasswd                |
| Nginx          | /etc/nginx/conf.d/*.conf, /etc/nginx/sites-enabled/*        |
| MySQL          | /etc/mysql/my.cnf, ~/.my.cnf, /var/lib/mysql/               |
| PostgreSQL     | /var/lib/postgresql/data/pg_hba.conf, ~/.pgpass              |
| MongoDB        | /etc/mongod.conf, /var/lib/mongodb/                          |
| Redis          | /etc/redis/redis.conf (requirepass), /var/lib/redis/dump.rdb |
| Docker         | /var/run/docker.sock, ~/.docker/config.json                  |
| Kubernetes     | ~/.kube/config, /etc/kubernetes/admin.conf                   |
| Jenkins        | /var/lib/jenkins/secrets/master.key, credentials.xml         |
| Ansible        | /etc/ansible/hosts, group_vars/all.yml (vault passwords)     |
| WordPress      | wp-config.php                                                |
| Laravel        | .env (APP_KEY, DB_PASSWORD)                                  |
| Django         | settings.py (SECRET_KEY, DATABASES)                          |
| Node.js        | .env, config.json, package.json (scripts with secrets)       |

## File Size & Time Filtering

```bash
# Recently modified files (last 7 days) — shows active configs
find / -mtime -7 -name "*.conf" -o -name "*.env" -o -name "*.yml" 2>/dev/null

# Large files that might be database dumps
find / -size +10M -name "*.sql" -o -name "*.dump" -o -name "*.bak" 2>/dev/null

# Files owned by specific user
find / -user www-data -name "*.conf" 2>/dev/null

# World-readable sensitive files (misconfiguration)
find /etc/ -maxdepth 2 -perm -o+r -name "*.conf" -ls 2>/dev/null
```
