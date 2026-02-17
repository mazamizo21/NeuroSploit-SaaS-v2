# OWASP ZAP Web Scanner Skill

## Overview
Complete methodology for using OWASP ZAP as an automated web application security
scanner. Covers daemon setup, spidering (traditional + AJAX), passive scanning,
active scanning, authenticated scanning, API scanning (OpenAPI/SOAP/GraphQL),
scripting, scan policies, context configuration, and reporting.
Everything is driven via ZAP's REST API for full automation.
This is the LLM agent's step-by-step playbook — follow it top to bottom.

## Scope Rules
1. Only scan explicitly authorized targets.
2. Active scanning generates significant traffic and may trigger WAF/IDS.
3. Use passive-only mode when stealth is required.
4. Respect rate limits — configure scan delay if needed.
5. Record scan scope, configuration, and all findings.

---

## Phase 1: ZAP Setup & Daemon Mode

### 1.1 Start ZAP in Daemon Mode
```bash
# Headless daemon (no GUI — API-only)
zap.sh -daemon -port 8090 -config api.key=zapkey -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# With specific memory allocation
zap.sh -daemon -port 8090 -config api.key=zapkey -Xmx4g

# Docker (preferred for consistent environments)
docker run -u zap -p 8090:8090 -d ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -port 8090 -host 0.0.0.0 \
  -config api.key=zapkey \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true
```

### 1.2 Verify ZAP is Running
```bash
# Check version
curl -s "http://zap:8090/JSON/core/view/version?apikey=zapkey"
# → {"version":"2.14.0"}

# Check API status
curl -s "http://zap:8090/JSON/core/view/homeDirectory?apikey=zapkey"
```

### 1.3 Python Client Setup
```python
from zapv2 import ZAPv2

zap = ZAPv2(
    apikey='zapkey',
    proxies={'http': 'http://zap:8090', 'https': 'http://zap:8090'}
)
print(f"ZAP version: {zap.core.version}")
```

---

## Phase 2: Context & Scope Configuration

### 2.1 Create a Context
A context defines the scope — what ZAP will scan.
```bash
# Create new context
CTX_ID=$(curl -s "http://zap:8090/JSON/context/action/newContext?apikey=zapkey&contextName=target_app" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['contextId'])")

echo "Context ID: $CTX_ID"
```

### 2.2 Define Scope (Include/Exclude)
```bash
# Include target in scope (regex)
curl -s "http://zap:8090/JSON/context/action/includeInContext?apikey=zapkey&contextName=target_app&regex=https?://target\\.com.*"

# Exclude logout / destructive endpoints
curl -s "http://zap:8090/JSON/context/action/excludeFromContext?apikey=zapkey&contextName=target_app&regex=.*logout.*"
curl -s "http://zap:8090/JSON/context/action/excludeFromContext?apikey=zapkey&contextName=target_app&regex=.*delete.*"
curl -s "http://zap:8090/JSON/context/action/excludeFromContext?apikey=zapkey&contextName=target_app&regex=.*unsubscribe.*"

# Verify scope
curl -s "http://zap:8090/JSON/context/view/context?apikey=zapkey&contextName=target_app"
```

### 2.3 Technology Configuration
Tell ZAP what tech stack is in use (focuses scan rules):
```bash
# Include specific technologies
curl -s "http://zap:8090/JSON/context/action/includeContextTechnologies?apikey=zapkey&contextName=target_app&technologyNames=PHP,MySQL,Apache,Linux"

# Exclude irrelevant technologies (reduces false positives)
curl -s "http://zap:8090/JSON/context/action/excludeContextTechnologies?apikey=zapkey&contextName=target_app&technologyNames=ASP,MSSQL,IIS"
```

---

## Phase 3: Authentication Setup

### 3.1 Form-Based Authentication
```bash
# Set authentication method
curl -s "http://zap:8090/JSON/authentication/action/setAuthenticationMethod?apikey=zapkey&contextId=$CTX_ID&authMethodName=formBasedAuthentication&authMethodConfigParams=loginUrl=http://target/login&loginRequestData=username%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D"

# Set login/logout indicators (regex in response body)
curl -s "http://zap:8090/JSON/authentication/action/setLoggedInIndicator?apikey=zapkey&contextId=$CTX_ID&loggedInIndicatorRegex=%5CQLogout%5CE"
curl -s "http://zap:8090/JSON/authentication/action/setLoggedOutIndicator?apikey=zapkey&contextId=$CTX_ID&loggedOutIndicatorRegex=%5CQLogin%5CE"
```

### 3.2 Add Users
```bash
# Create user
USER_ID=$(curl -s "http://zap:8090/JSON/users/action/newUser?apikey=zapkey&contextId=$CTX_ID&name=testuser" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['userId'])")

# Set credentials
curl -s "http://zap:8090/JSON/users/action/setAuthenticationCredentials?apikey=zapkey&contextId=$CTX_ID&userId=$USER_ID&authCredentialsConfigParams=username%3Dtestuser%26password%3Dtestpass123"

# Enable user
curl -s "http://zap:8090/JSON/users/action/setUserEnabled?apikey=zapkey&contextId=$CTX_ID&userId=$USER_ID&enabled=true"

# Set forced user (auto-authenticate for scanning)
curl -s "http://zap:8090/JSON/forcedUser/action/setForcedUser?apikey=zapkey&contextId=$CTX_ID&userId=$USER_ID"
curl -s "http://zap:8090/JSON/forcedUser/action/setForcedUserModeEnabled?apikey=zapkey&boolean=true"
```

### 3.3 Token/Header-Based Authentication (APIs)
```bash
# For Bearer token / API key authentication
curl -s "http://zap:8090/JSON/authentication/action/setAuthenticationMethod?apikey=zapkey&contextId=$CTX_ID&authMethodName=scriptBasedAuthentication&authMethodConfigParams=scriptName=jwt_auth.js"

# Or add a persistent authorization header via replacer
curl -s "http://zap:8090/JSON/replacer/action/addRule?apikey=zapkey&description=AuthHeader&enabled=true&matchType=REQ_HEADER&matchRegex=false&matchString=Authorization&replacement=Bearer+YOUR_JWT_TOKEN&initiators="

# Session management — cookie-based (default) or header-based
curl -s "http://zap:8090/JSON/sessionManagement/action/setSessionManagementMethod?apikey=zapkey&contextId=$CTX_ID&methodName=cookieBasedSessionManagement"
```

---

## Phase 4: Spidering (Crawling)

### 4.1 Traditional Spider
```bash
# Start spider
SPIDER_ID=$(curl -s "http://zap:8090/JSON/spider/action/scan?apikey=zapkey&url=http://target/&maxChildren=100&recurse=true&contextName=target_app" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['scan'])")

# Monitor progress (0-100%)
while true; do
  STATUS=$(curl -s "http://zap:8090/JSON/spider/view/status?apikey=zapkey&scanId=$SPIDER_ID" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "Spider progress: $STATUS%"
  [ "$STATUS" = "100" ] && break
  sleep 5
done

# View results
curl -s "http://zap:8090/JSON/spider/view/results?apikey=zapkey&scanId=$SPIDER_ID" | python3 -m json.tool

# Full results — all discovered URLs
curl -s "http://zap:8090/JSON/spider/view/fullResults?apikey=zapkey&scanId=$SPIDER_ID"
```

### 4.2 AJAX Spider (JavaScript-Heavy Apps)
For SPAs (React, Angular, Vue) that render content via JavaScript:
```bash
# Start AJAX spider (uses headless browser)
curl -s "http://zap:8090/JSON/ajaxSpider/action/scan?apikey=zapkey&url=http://target/&inScope=true"

# Monitor AJAX spider status
curl -s "http://zap:8090/JSON/ajaxSpider/view/status?apikey=zapkey"
# Status: "running" or "stopped"

# Get number of results
curl -s "http://zap:8090/JSON/ajaxSpider/view/numberOfResults?apikey=zapkey"

# View discovered resources
curl -s "http://zap:8090/JSON/ajaxSpider/view/fullResults?apikey=zapkey"

# Stop AJAX spider when sufficient coverage
curl -s "http://zap:8090/JSON/ajaxSpider/action/stop?apikey=zapkey"
```

### 4.3 OpenAPI / SOAP / GraphQL Import
For API targets, import the API definition directly:
```bash
# Import OpenAPI/Swagger spec
curl -s "http://zap:8090/JSON/openapi/action/importUrl?apikey=zapkey&url=http://target/api/v1/openapi.json"
# Or from file
curl -s "http://zap:8090/JSON/openapi/action/importFile?apikey=zapkey&file=/path/to/openapi.yaml"

# Import SOAP WSDL
curl -s "http://zap:8090/JSON/soap/action/importUrl?apikey=zapkey&url=http://target/ws?wsdl"

# GraphQL introspection
curl -s "http://zap:8090/JSON/graphql/action/importUrl?apikey=zapkey&url=http://target/graphql&endUrl=http://target/graphql"
```

---

## Phase 5: Passive Scanning

### 5.1 How Passive Scanning Works
Passive scanning analyzes all traffic that passes through ZAP without sending
any additional requests. It runs automatically on all proxied/spidered traffic.

```bash
# View passive scan queue size
curl -s "http://zap:8090/JSON/pscan/view/recordsToScan?apikey=zapkey"

# Wait for passive scan to complete
while true; do
  REMAINING=$(curl -s "http://zap:8090/JSON/pscan/view/recordsToScan?apikey=zapkey" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['recordsToScan'])")
  echo "Passive scan remaining: $REMAINING"
  [ "$REMAINING" = "0" ] && break
  sleep 3
done
```

### 5.2 Passive Scan Findings
Passive scan detects issues like:
- Missing security headers (CSP, X-Frame-Options, HSTS, etc.)
- Information disclosure (server version, stack traces, comments)
- Insecure cookies (missing HttpOnly, Secure, SameSite)
- Mixed content (HTTP resources on HTTPS page)
- Open redirects
- Private IP disclosure
- Cacheable sensitive content
- Weak authentication mechanisms

### 5.3 Configure Passive Scan Rules
```bash
# List all passive scan rules
curl -s "http://zap:8090/JSON/pscan/view/scanners?apikey=zapkey" | python3 -m json.tool

# Disable a noisy rule (by ID)
curl -s "http://zap:8090/JSON/pscan/action/disableScanners?apikey=zapkey&ids=10096"

# Set scan rule threshold (OFF, LOW, MEDIUM, HIGH)
curl -s "http://zap:8090/JSON/pscan/action/setScannerAlertThreshold?apikey=zapkey&id=10096&alertThreshold=HIGH"
```

---

## Phase 6: Active Scanning

### 6.1 Start Active Scan
Active scanning sends attack payloads to find vulnerabilities.
**⚠ Requires explicit authorization — generates significant traffic.**
```bash
# Scan entire site (uses spider results as seed)
ASCAN_ID=$(curl -s "http://zap:8090/JSON/ascan/action/scan?apikey=zapkey&url=http://target/&recurse=true&inScopeOnly=true&contextName=target_app" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['scan'])")

# Scan specific URL only
ASCAN_ID=$(curl -s "http://zap:8090/JSON/ascan/action/scan?apikey=zapkey&url=http://target/vulnerable-page&recurse=false" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['scan'])")

# Monitor progress
while true; do
  STATUS=$(curl -s "http://zap:8090/JSON/ascan/view/status?apikey=zapkey&scanId=$ASCAN_ID" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "Active scan progress: $STATUS%"
  [ "$STATUS" = "100" ] && break
  sleep 10
done
```

### 6.2 Scan Policies
Customize what active scan tests run:
```bash
# List scan policies
curl -s "http://zap:8090/JSON/ascan/view/policies?apikey=zapkey&scanPolicyName=Default+Policy"

# Key scan rule categories:
# 40012 — Cross Site Scripting (Reflected)
# 40014 — Cross Site Scripting (Persistent)
# 40018 — SQL Injection
# 40019 — SQL Injection (MySQL)
# 40020 — SQL Injection (Hypersonic/HSQL)
# 40021 — SQL Injection (Oracle)
# 40022 — SQL Injection (PostgreSQL)
# 90019 — Server Side Include
# 90020 — Remote OS Command Injection
# 40003 — CRLF Injection
# 40008 — Parameter Tampering
# 40009 — Server Side Request Forgery
# 6     — Path Traversal
# 7     — Remote File Inclusion

# Enable/disable specific rules
curl -s "http://zap:8090/JSON/ascan/action/enableScanners?apikey=zapkey&ids=40018,40019,40012"
curl -s "http://zap:8090/JSON/ascan/action/disableScanners?apikey=zapkey&ids=90020"

# Set scan strength (LOW, MEDIUM, HIGH, INSANE)
curl -s "http://zap:8090/JSON/ascan/action/setScannerAttackStrength?apikey=zapkey&id=40018&attackStrength=HIGH"

# Set alert threshold
curl -s "http://zap:8090/JSON/ascan/action/setScannerAlertThreshold?apikey=zapkey&id=40018&alertThreshold=LOW"
```

### 6.3 Scan Control
```bash
# Pause active scan
curl -s "http://zap:8090/JSON/ascan/action/pause?apikey=zapkey&scanId=$ASCAN_ID"

# Resume active scan
curl -s "http://zap:8090/JSON/ascan/action/resume?apikey=zapkey&scanId=$ASCAN_ID"

# Stop active scan
curl -s "http://zap:8090/JSON/ascan/action/stop?apikey=zapkey&scanId=$ASCAN_ID"

# Remove completed scan
curl -s "http://zap:8090/JSON/ascan/action/removeScan?apikey=zapkey&scanId=$ASCAN_ID"
```

---

## Phase 7: Results & Reporting

### 7.1 View Alerts
```bash
# Get all alerts
curl -s "http://zap:8090/JSON/alert/view/alerts?apikey=zapkey&baseurl=http://target/&start=0&count=100" \
  | python3 -m json.tool

# Alert summary by risk level
curl -s "http://zap:8090/JSON/alert/view/alertsSummary?apikey=zapkey&baseurl=http://target/" \
  | python3 -m json.tool
# Returns: {"High":2,"Medium":5,"Low":12,"Informational":20}

# Get alerts by risk level
curl -s "http://zap:8090/JSON/alert/view/alertsByRisk?apikey=zapkey&url=http://target/"

# Get specific alert details
curl -s "http://zap:8090/JSON/alert/view/alert?apikey=zapkey&id=ALERT_ID"
```

### 7.2 Alert Fields
Each alert contains:
```json
{
  "id": "123",
  "pluginId": "40018",
  "alert": "SQL Injection",
  "risk": "High",
  "confidence": "Medium",
  "url": "http://target/search?q=test",
  "param": "q",
  "attack": "q=test' AND '1'='1",
  "evidence": "SQL syntax error",
  "description": "...",
  "solution": "...",
  "reference": "https://owasp.org/...",
  "cweid": "89",
  "wascid": "19"
}
```

### 7.3 Generate Reports
```bash
# HTML report (comprehensive)
curl -s "http://zap:8090/OTHER/core/other/htmlreport?apikey=zapkey" > zap_report.html

# JSON report (machine-readable)
curl -s "http://zap:8090/OTHER/core/other/jsonreport?apikey=zapkey" > zap_report.json

# XML report
curl -s "http://zap:8090/OTHER/core/other/xmlreport?apikey=zapkey" > zap_report.xml

# Markdown report
curl -s "http://zap:8090/OTHER/core/other/mdreport?apikey=zapkey" > zap_report.md
```

### 7.4 Parse Results into Evidence
```python
import json, requests

ZAP = "http://zap:8090"
KEY = "zapkey"

alerts = requests.get(f"{ZAP}/JSON/alert/view/alerts",
    params={"apikey": KEY, "baseurl": "http://target/"}).json()["alerts"]

findings = []
for a in alerts:
    if a["risk"] in ("High", "Medium"):
        findings.append({
            "title": a["alert"],
            "severity": a["risk"],
            "confidence": a["confidence"],
            "url": a["url"],
            "parameter": a.get("param", ""),
            "attack": a.get("attack", ""),
            "evidence": a.get("evidence", ""),
            "cwe": a.get("cweid", ""),
            "solution": a.get("solution", "")
        })

with open("findings.json", "w") as f:
    json.dump(findings, f, indent=2)

print(f"[+] Exported {len(findings)} High/Medium findings")
```

---

## Phase 8: ZAP Scripting

### 8.1 Script Types
ZAP supports scripts for custom scanning logic:
- **Active Rules** — custom attack payloads
- **Passive Rules** — custom response analysis
- **Authentication** — custom login flows
- **HTTP Sender** — modify requests/responses in-flight
- **Targeted** — run against specific URLs on demand
- **Stand Alone** — general-purpose scripts

### 8.2 Load and Run Scripts
```bash
# List script engines
curl -s "http://zap:8090/JSON/script/view/listEngines?apikey=zapkey"

# Load a script
curl -s "http://zap:8090/JSON/script/action/load?apikey=zapkey&scriptName=custom_scan&scriptType=active&scriptEngine=ECMAScript&fileName=/path/to/script.js"

# Enable script
curl -s "http://zap:8090/JSON/script/action/enable?apikey=zapkey&scriptName=custom_scan"

# Run standalone script
curl -s "http://zap:8090/JSON/script/action/runStandAloneScript?apikey=zapkey&scriptName=custom_scan"
```

### 8.3 Automation Framework (ZAP 2.11+)
```yaml
# automation.yaml — declarative scan configuration
env:
  contexts:
    - name: "target_app"
      urls: ["http://target/"]
      includePaths: ["http://target/.*"]
      excludePaths: ["http://target/logout.*"]
      authentication:
        method: "form"
        parameters:
          loginPageUrl: "http://target/login"
          loginRequestUrl: "http://target/login"
          loginRequestBody: "username={%username%}&password={%password%}"
        verification:
          method: "response"
          loggedInRegex: "\\QLogout\\E"
      users:
        - name: "testuser"
          credentials:
            username: "testuser"
            password: "testpass123"
jobs:
  - type: "spider"
    parameters:
      url: "http://target/"
      maxDuration: 5
      maxChildren: 100
  - type: "spiderAjax"
    parameters:
      url: "http://target/"
      maxDuration: 5
  - type: "passiveScan-wait"
    parameters:
      maxDuration: 10
  - type: "activeScan"
    parameters:
      url: "http://target/"
      maxScanDuration: 30
  - type: "report"
    parameters:
      template: "traditional-html"
      reportDir: "/tmp/"
      reportFile: "zap_report"
```

```bash
# Run automation plan
zap.sh -cmd -autorun /path/to/automation.yaml
```

---

## Standard Workflow — Full Scan Recipe

```bash
ZAP="http://zap:8090"
KEY="zapkey"
TARGET="http://target"

# 1. Create context & set scope
CTX=$(curl -s "$ZAP/JSON/context/action/newContext?apikey=$KEY&contextName=scan" | python3 -c "import sys,json;print(json.load(sys.stdin)['contextId'])")
curl -s "$ZAP/JSON/context/action/includeInContext?apikey=$KEY&contextName=scan&regex=http://target.*"

# 2. Spider
SID=$(curl -s "$ZAP/JSON/spider/action/scan?apikey=$KEY&url=$TARGET&recurse=true" | python3 -c "import sys,json;print(json.load(sys.stdin)['scan'])")
while [ "$(curl -s "$ZAP/JSON/spider/view/status?apikey=$KEY&scanId=$SID" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])")" != "100" ]; do sleep 5; done

# 3. AJAX Spider (if SPA)
curl -s "$ZAP/JSON/ajaxSpider/action/scan?apikey=$KEY&url=$TARGET&inScope=true"
sleep 60
curl -s "$ZAP/JSON/ajaxSpider/action/stop?apikey=$KEY"

# 4. Wait for passive scan
while [ "$(curl -s "$ZAP/JSON/pscan/view/recordsToScan?apikey=$KEY" | python3 -c "import sys,json;print(json.load(sys.stdin)['recordsToScan'])")" != "0" ]; do sleep 3; done

# 5. Active scan
AID=$(curl -s "$ZAP/JSON/ascan/action/scan?apikey=$KEY&url=$TARGET&recurse=true&inScopeOnly=true" | python3 -c "import sys,json;print(json.load(sys.stdin)['scan'])")
while [ "$(curl -s "$ZAP/JSON/ascan/view/status?apikey=$KEY&scanId=$AID" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])")" != "100" ]; do sleep 10; done

# 6. Get results
curl -s "$ZAP/JSON/alert/view/alertsSummary?apikey=$KEY&baseurl=$TARGET"
curl -s "$ZAP/OTHER/core/other/htmlreport?apikey=$KEY" > report.html
echo "[+] Report saved to report.html"
```

---

## Decision Tree — ZAP Scanning Flow

```
TARGET URL IDENTIFIED
│
├── Start ZAP daemon
│
├── CONFIGURE
│   ├── Create context + set scope
│   ├── Exclude destructive endpoints
│   ├── Set technology profile
│   └── Configure authentication (if needed)
│
├── DISCOVERY
│   ├── Traditional spider (HTML apps)
│   ├── AJAX spider (SPA/JavaScript apps)
│   └── API import (OpenAPI/SOAP/GraphQL)
│
├── PASSIVE SCAN (automatic, zero noise)
│   ├── Wait for completion
│   └── Review passive findings
│
├── ACTIVE SCAN (requires authorization)
│   ├── Configure scan policy
│   ├── Set attack strength
│   ├── Start scan + monitor progress
│   └── Review active findings
│
└── REPORT
    ├── Get alert summary
    ├── Export findings as JSON
    ├── Generate HTML/XML/Markdown report
    └── Parse into evidence.json / findings.json
```

---

## Evidence Collection
1. `vulnerabilities.json` — all alerts with risk/confidence/CWE
2. `evidence.json` — attack payloads, responses, proof of vulnerability
3. `zap_report.html` — full HTML report for client delivery
4. Spider results showing application coverage
5. Scan configuration and scope documentation

## Evidence Consolidation
Use the Python parsing script (Phase 7.4) to convert ZAP alerts into
standardized `findings.json`. Map CWE IDs to MITRE ATT&CK techniques.

## MITRE ATT&CK Mappings
- T1190 — Exploit Public-Facing Application
- T1189 — Drive-by Compromise
- T1059.007 — JavaScript

## Deep Dives
Load references when needed:
1. ZAP API reference: `references/zap_api.md`
2. Scan policy tuning: `references/scan_policies.md`
3. Authentication recipes: `references/auth_recipes.md`
4. Automation framework: `references/automation.md`

## Success Criteria
- Spider discovers all application endpoints
- Passive scan completes with findings categorized
- Active scan completes (if authorized) with valid alerts
- No false positives above Medium confidence
- Report generated in required format
- All findings documented with evidence
