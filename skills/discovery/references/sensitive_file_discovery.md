# Sensitive File Discovery Reference

## Linux Credential Files

### System Credentials
```bash
cat /etc/shadow 2>/dev/null             # Password hashes (root)
cat /etc/passwd                          # User accounts (world-readable)
cat /etc/master.passwd 2>/dev/null      # BSD shadow equivalent
cat /etc/security/opasswd 2>/dev/null   # Old passwords (PAM)
```

### SSH Keys & Config
```bash
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "id_dsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "known_hosts" 2>/dev/null
cat ~/.ssh/config 2>/dev/null           # SSH config with hosts/keys
ls -la /root/.ssh/ 2>/dev/null          # Root SSH keys (if readable)
find /home -name ".ssh" -type d 2>/dev/null  # All user SSH dirs
```

### History Files
```bash
find / -name ".*_history" -o -name ".*history" 2>/dev/null
cat ~/.bash_history                      # Bash history (may contain passwords)
cat ~/.mysql_history 2>/dev/null        # MySQL command history
cat ~/.psql_history 2>/dev/null         # PostgreSQL history
cat ~/.python_history 2>/dev/null       # Python REPL history
cat ~/.node_repl_history 2>/dev/null    # Node.js REPL history
cat ~/.rediscli_history 2>/dev/null     # Redis CLI history
cat ~/.lesshst 2>/dev/null              # less history
cat ~/.viminfo 2>/dev/null              # Vim history (may show edited files)
```

### Configuration Files with Credentials
```bash
# Web application configs
find / -name "wp-config.php" 2>/dev/null        # WordPress
find / -name "configuration.php" 2>/dev/null    # Joomla
find / -name "settings.php" 2>/dev/null         # Drupal
find / -name "config.php" 2>/dev/null           # Various PHP apps
find / -name "database.yml" 2>/dev/null         # Rails database config
find / -name ".env" 2>/dev/null                 # Environment files (common)
find / -name "application.properties" 2>/dev/null  # Java Spring
find / -name "application.yml" 2>/dev/null      # Java Spring YAML
find / -name "settings.py" 2>/dev/null          # Django settings
find / -name "appsettings.json" 2>/dev/null     # .NET config

# Database configs
cat /etc/mysql/my.cnf 2>/dev/null               # MySQL config
cat /etc/mysql/debian.cnf 2>/dev/null           # MySQL Debian auto-password
cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null  # PostgreSQL auth
cat /var/lib/pgsql/data/pg_hba.conf 2>/dev/null     # PostgreSQL RHEL

# Service configs
cat /etc/ldap/ldap.conf 2>/dev/null             # LDAP config
cat /etc/openldap/ldap.conf 2>/dev/null         # LDAP RHEL
cat /etc/samba/smb.conf 2>/dev/null             # Samba config
cat /etc/vsftpd.conf 2>/dev/null                # FTP config
cat /etc/tomcat*/tomcat-users.xml 2>/dev/null   # Tomcat users
find / -name "tomcat-users.xml" 2>/dev/null
```

### Grep for Passwords in Files
```bash
# Search for password strings in config files
grep -rli "password" /etc/ 2>/dev/null
grep -rli "passwd" /etc/ 2>/dev/null
grep -rn "password\s*=" /var/www/ 2>/dev/null
grep -rn "DB_PASSWORD\|DB_PASS\|MYSQL_PASSWORD\|POSTGRES_PASSWORD" /var/www/ /opt/ /srv/ 2>/dev/null
grep -rn "api_key\|apikey\|api-key\|secret_key\|access_key" /var/www/ /opt/ /srv/ 2>/dev/null

# Search common directories
grep -rli "password\|passwd\|secret\|credential" /opt/ /var/www/ /srv/ /home/ 2>/dev/null | head -30
```

### Key and Certificate Files
```bash
find / -name "*.pem" -o -name "*.key" -o -name "*.crt" -o -name "*.cer" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks" -o -name "*.keystore" 2>/dev/null
find / -name "*.gpg" -o -name "*.pgp" 2>/dev/null
ls -la /etc/ssl/private/ 2>/dev/null    # SSL private keys
```

### Database Files
```bash
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.mdb" -o -name "*.accdb" 2>/dev/null
find / -name "*.sql" -o -name "*.dump" 2>/dev/null
locate *.db 2>/dev/null                  # Fast search via locate DB
```

### Backup and Archive Files
```bash
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.orig" -o -name "*.save" 2>/dev/null
find / -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.7z" 2>/dev/null | head -30
find / -name "*.kdbx" -o -name "*.kdb" 2>/dev/null  # KeePass databases
```

### Cloud Credential Files
```bash
cat ~/.aws/credentials 2>/dev/null       # AWS credentials
cat ~/.aws/config 2>/dev/null            # AWS config
cat ~/.azure/accessTokens.json 2>/dev/null  # Azure tokens
cat ~/.config/gcloud/credentials.db 2>/dev/null  # GCP credentials
cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null
find / -name "credentials" -path "*/.aws/*" 2>/dev/null
find / -name ".boto" 2>/dev/null         # GCS boto config
cat /etc/boto.cfg 2>/dev/null            # System boto config
```

### Docker/Container Secrets
```bash
cat /.dockerenv 2>/dev/null              # Check if in container
cat /run/secrets/* 2>/dev/null           # Docker secrets
env | grep -iE "password|secret|key|token|api"  # Env var secrets
find / -name "docker-compose.yml" -o -name "docker-compose.yaml" 2>/dev/null
```

---

## Windows Credential Locations

### Registry Credentials
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultPassword DefaultUserName"
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s 2>nul
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s 2>nul  :: PuTTY saved sessions
reg query HKCU\Software\ORL\WinVNC3\Password 2>nul           :: VNC password
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password 2>nul  :: RealVNC
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Unattend" 2>nul
```

### SAM/SYSTEM Files
```cmd
:: Copy SAM/SYSTEM for offline cracking (requires SYSTEM/admin)
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
reg save HKLM\SECURITY C:\temp\security.hive

:: Check for backup copies
dir C:\Windows\repair\SAM 2>nul
dir C:\Windows\System32\config\RegBack\SAM 2>nul
```

### Unattend Files (Installation Passwords)
```cmd
dir /s /b C:\*unattend.xml C:\*sysprep.xml C:\*unattended.xml 2>nul
type C:\Windows\Panther\Unattend.xml 2>nul
type C:\Windows\Panther\unattend\Unattend.xml 2>nul
type C:\Windows\System32\Sysprep\unattend.xml 2>nul
```

### Credential Manager & DPAPI
```powershell
cmdkey /list                             # Stored credentials
vaultcmd /listcreds:"Windows Credentials" /all  # Windows Vault
vaultcmd /listcreds:"Web Credentials" /all      # Web Vault
dir %APPDATA%\Microsoft\Credentials\     # DPAPI credential blobs
dir %LOCALAPPDATA%\Microsoft\Credentials\
```

### Browser Credentials
```cmd
:: Chrome credentials (encrypted with DPAPI)
dir "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" 2>nul
dir "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies" 2>nul

:: Firefox credentials
dir "%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json" 2>nul
dir "%APPDATA%\Mozilla\Firefox\Profiles\*\key4.db" 2>nul

:: Edge
dir "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data" 2>nul
```

### Windows Password Search
```cmd
findstr /si password *.txt *.xml *.ini *.cfg *.config
findstr /si password *.ps1 *.bat *.cmd *.vbs
findstr /spin "password" *.*
dir /s /b *pass* *cred* *vnc* *.config 2>nul
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul
```

### PowerShell Transcript/History
```powershell
# PowerShell history
Get-Content (Get-PSReadLineOption).HistorySavePath
# Transcripts
dir C:\Transcripts\ -Recurse 2>$null
dir $env:USERPROFILE\Documents\PowerShell_transcript* 2>$null
```

### WiFi Passwords
```cmd
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear
```

### IIS Configuration
```cmd
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config 2>nul
type C:\inetpub\wwwroot\web.config 2>nul
dir /s /b C:\inetpub\*.config 2>nul
```

### Cloud Credentials (Windows)
```cmd
dir %USERPROFILE%\.aws\credentials 2>nul
dir %USERPROFILE%\.azure\accessTokens.json 2>nul
dir %APPDATA%\gcloud\credentials.db 2>nul
dir %APPDATA%\gcloud\application_default_credentials.json 2>nul
```

---

## Universal Sensitive File Patterns

### Quick One-Liners
```bash
# Linux — find everything interesting fast
find / -readable -type f \( -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "*.kdbx" -o -name "*.sql" -o -name "*.bak" -o -name "wp-config*" -o -name ".*history" \) 2>/dev/null | head -100
```

```powershell
# Windows — comprehensive search
Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.ini,*.cfg,*.config,*.ps1,*.bat,*.cmd -Recurse -ErrorAction SilentlyContinue |
    Select-String -Pattern "password|passwd|pwd|secret|credential|api_key|connectionstring" -List |
    Select-Object Path, LineNumber -First 50
```
