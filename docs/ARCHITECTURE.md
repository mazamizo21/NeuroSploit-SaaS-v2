# TazoSploit — Architecture Documentation

> **TazoSploit** is an AI-powered penetration testing platform that autonomously executes the full kill chain — from reconnaissance through exploitation, post-exploitation, and reporting — inside hardened Kali Linux containers orchestrated by an LLM-driven agent. It maps every action to MITRE ATT&CK, tracks 17+ vulnerability types in real time, and streams findings to a live dashboard. Think "Metasploit meets Claude" with a SaaS control plane, multi-tenant isolation, 125 injectable skills, and a supervisor that watches the agent and course-corrects when it stalls.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Components](#core-components)
3. [Data Flow](#data-flow)
4. [Kill Chain Coverage](#kill-chain-coverage)
5. [Configuration](#configuration)
6. [Key Design Decisions](#key-design-decisions)
7. [File Map](#file-map)

---

## System Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          CONTROL PLANE (control-net)                         │
│                                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────────────────┐    │
│  │ Frontend  │  │   API    │  │ Postgres │  │    MinIO (Evidence S3)    │    │
│  │ Next.js   │  │ FastAPI  │  │  15-alp  │  │    Loot / Artifacts      │    │
│  │ :3000     │  │ :8000    │  │          │  │    :9000 / :9001         │    │
│  └─────┬─────┘  └────┬─────┘  └─────┬────┘  └───────────────────────────┘    │
│        │              │              │                                        │
│        └──────────────┼──────────────┘                                        │
│                       │                                                      │
│              ┌────────┴────────┐                                             │
│              │     Redis       │◄──── pub/sub: job output, kill signals      │
│              │   7-alpine      │◄──── queues: job_queue, tenant queues       │
│              │                 │◄──── state:  live_stats, vuln counts        │
│              └────────┬────────┘                                             │
│                       │                                                      │
├───────────────────────┼──────────────────────────────────────────────────────┤
│                 EXECUTION PLANE (exec-net)                                   │
│                       │                                                      │
│  ┌──────────┐  ┌──────┴──────┐  ┌──────────────┐                           │
│  │Scheduler │  │   Worker    │  │  Supervisor   │                           │
│  │ FastAPI   │  │  ×2 repl.  │  │  Heuristic +  │                           │
│  │ :9001     │  │  Docker SDK │  │  LLM Triage   │                           │
│  └──────────┘  └──────┬──────┘  └──────────────┘                           │
│                       │                                                      │
├───────────────────────┼──────────────────────────────────────────────────────┤
│                 KALI PLANE (kali-net + lab-net)                              │
│                       │                                                      │
│  ┌────────────────────┴────────────────────┐  ┌──────────────┐              │
│  │         Kali Executor  ×2 replicas      │  │ DOM Renderer │              │
│  │  ┌─────────────────────────────────┐    │  │ Playwright   │              │
│  │  │   dynamic_agent.py (6570 LOC)  │    │  │ :8080        │              │
│  │  │   ┌─────────────┐ ┌──────────┐ │    │  └──────────────┘              │
│  │  │   │ LLM Client  │ │  Skills  │ │    │                                │
│  │  │   │ (proxy/     │ │  Engine  │ │    │  ┌──────────────────────┐      │
│  │  │   │  direct)    │ │ 125 YAML │ │    │  │  Tunnel Gateway      │      │
│  │  │   └─────────────┘ └──────────┘ │    │  │  WireGuard VPN (Go)  │      │
│  │  │   ┌──────────┐ ┌────────────┐  │    │  │  :51820/udp          │      │
│  │  │   │  Arsenal │ │Auto-Tracker│  │    │  └──────────────────────┘      │
│  │  │   │  Memory  │ │ 17+ Types  │  │    │                                │
│  │  └───┴──────────┴─┴────────────┴──┘    │                                │
│  │  150+ Kali tools, SecLists, PEASS-ng   │                                │
│  └─────────────────────────────────────────┘                                │
│                       │                                                      │
│              ┌────────┴────────┐                                             │
│              │   Lab Targets   │  (docker-compose.lab.yml)                   │
│              │   DVWA, Juice   │                                             │
│              │   Shop, etc.    │                                             │
│              └─────────────────┘                                             │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Services at a Glance

| Service | Container | Tech | Purpose |
|---------|-----------|------|---------|
| **API** | `tazosploit-api` | FastAPI (Python 3.11) | REST API, LLM proxy, job lifecycle, auth, WebSocket |
| **Frontend** | `tazosploit-frontend` | Next.js | Dashboard, Live Intelligence, findings feed |
| **Scheduler** | `tazosploit-scheduler` | FastAPI | Distributes jobs from tenant queues to workers |
| **Worker** | `tazosploit-worker-{1,2}` | Python + Docker SDK | Picks jobs, exec's into Kali containers, pushes findings |
| **Supervisor** | `tazosploit-supervisor` | Python + Redis | Monitors agent behavior, detects stalls, LLM-augmented triage |
| **Kali Executor** | `tazosploit-kali-{1,2}` | Kali Rolling + 150 tools | The AI agent runs here — full Kali toolchain |
| **DOM Renderer** | `tazosploit-dom-renderer` | Playwright | Headless browser for JavaScript-heavy targets |
| **Postgres** | `tazosploit-postgres` | PostgreSQL 15 | Jobs, tenants, users, scopes, findings, audit logs |
| **Redis** | `tazosploit-redis` | Redis 7 | Job queues, pub/sub streaming, live stats |
| **MinIO** | `tazosploit-minio` | S3-compatible | Evidence/loot artifact storage |
| **Tunnel Gateway** | `tazosploit-tunnel` | Go + WireGuard | VPN gateway for internal network access |

### Networks

| Network | Purpose |
|---------|---------|
| `tazosploit-control` | API ↔ Postgres ↔ Redis ↔ Frontend ↔ MinIO |
| `tazosploit-execution` | Scheduler ↔ Worker ↔ Redis ↔ Supervisor |
| `tazosploit-kali` | Worker ↔ Kali containers ↔ DOM Renderer (internet-enabled for LLM API calls) |
| `tazosploit-lab` | Kali ↔ Vulnerable lab targets (external network, created by `docker-compose.lab.yml`) |

---

## Core Components

### 1. Control Plane — FastAPI API

**Path:** `control-plane/`  
**Entry:** `control-plane/api/__init__.py` → FastAPI app  
**Key files:**

| File | Lines | Purpose |
|------|-------|---------|
| `api/routers/jobs.py` | ~1619 | Job CRUD, findings ingest, live-intel endpoint, logs, output polling |
| `api/routers/internal_llm.py` | ~591 | LLM proxy — routes to 20+ providers, thinking support, retry/backoff |
| `api/routers/websocket.py` | ~358 | Real-time output streaming via WebSocket |
| `api/models.py` | ~708 | SQLAlchemy ORM: Tenant, User, Scope, Job, Finding, AuditLog, Policy, Loot |
| `api/auth.py` | ~110 | JWT auth, role-based access (admin/operator/viewer/auditor) |
| `api/database.py` | ~48 | Async SQLAlchemy + PostgreSQL session factory |
| `api/utils/redact.py` | — | Defense-in-depth secret redaction (sk-*, Bearer tokens, Zhipu keys) |
| `api/utils/crypto.py` | — | AES encryption for tenant API keys |

**API Routers (18 total):**

```
jobs.py           internal_llm.py    auth_router.py    scopes.py
tenants.py        settings.py        dashboard.py      agents.py
scheduled_jobs.py reports.py         audit.py          terminal.py
attack_graphs.py  simulations.py     policies.py       websocket.py
loot.py           mitre.py           workspaces.py
```

#### Job Lifecycle

```
POST /api/v1/jobs
  ├── Validate scope, targets, intensity, phase, exploit_mode
  ├── Check tenant quotas (concurrent job limit)
  ├── Create Job record (PostgreSQL)
  ├── Write AuditLog entry
  ├── LPUSH to Redis: tenant:{id}:job_queue
  └── Set supervisor overrides in Redis (if specified)

GET /api/v1/jobs/{id}/live-intel
  ├── Read from /pentest/output/{job_id}/ volume
  ├── Parse: nmap_fast.gnmap, tech_fingerprint.json, gobuster.txt
  ├── Parse: vuln_tracker.json, arsenal.json, handoff.json
  └── Return: ports, tech_stack, web_paths, exploits_matched,
              vulnerabilities, exploitation_attempts, credentials,
              access_level, tools_used, findings
```

#### LLM Proxy (`/api/internal/llm/chat`)

The proxy is the single point of LLM access for all Kali containers. This keeps provider API keys **out of the executor containers** entirely.

**Supported providers (20+):**
```
anthropic, claude, openai, openai-codex, codex, openrouter,
moonshot, synthetic, venice, minimax, qwen-portal, xiaomi,
ollama, lmstudio, lm-studio, cerebras, z.ai, zai, zhipu, glm
```

**Key features:**
- Automatic provider detection and routing
- Thinking/reasoning support (`thinking: {type: "enabled"}` for GLM-5, Claude)
- Thinking-level directives (minimal → low → medium → high → xhigh)
- Claude subscription token (OAuth `sk-ant-oat*`) support — mimics Claude Code headers
- Exponential backoff with jitter (configurable: `LLM_PROXY_RETRY_MAX`, `LLM_PROXY_RETRY_BASE_SECONDS`)
- Dual API style support: OpenAI-compatible (`/chat/completions`) and Anthropic (`/messages`)
- Per-tenant encrypted credentials with DB-based provider config
- Environment fallback when DB config unavailable

---

### 2. Execution Plane — Workers & Scheduler

**Path:** `execution-plane/`

#### Scheduler (`execution-plane/scheduler/main.py`, ~167 LOC)

- Polls tenant job queues (`tenant:{id}:job_queue`) via Redis BRPOP
- Enforces `MAX_CONCURRENT_JOBS` (default: 10)
- Dispatches to shared `worker:job_queue`
- Listens for job completion via Redis pub/sub to release slots
- Handles cancel prevention (marks terminal jobs in Redis to prevent re-dispatch)

#### Worker (`execution-plane/worker/main.py`, ~1628 LOC)

The worker is the bridge between the control plane and Kali containers:

```python
# Simplified execution flow
async def _execute_job(self, job):
    job_details = await self._get_job_from_api(job_id)
    container = await self._get_kali_container()  # Docker SDK
    
    # Build objective from phase + target + exploit_mode
    cmd = ["python3", "/opt/tazosploit/dynamic_agent.py",
           "--target", target, "--objective", objective,
           "--max-iterations", str(max_iterations),
           "--output-dir", output_dir]
    
    # Stream output line-by-line to Redis pub/sub
    # Every 30s: push live findings + loot to API
    # Monitor cancel event via Redis subscription
    result = await self._run_in_container(container, job_details, job_id)
    
    # Post-execution: read vuln_tracker.json, arsenal.json, findings.json
    await self._post_findings_and_loot(job_id, tenant_id, result)
```

**Key responsibilities:**
- **Container orchestration:** Finds running Kali containers by label/name/image
- **Live streaming:** Every output line → Redis pub/sub (`job:{id}:output`) + buffer list
- **Real-time finding push:** Every 30s reads `vuln_tracker.json` and pushes proven findings to API
- **Loot extraction:** Credentials from `arsenal.json` → loot API with duplicate prevention
- **Token tracking:** Aggregates `llm_interactions.jsonl` and pushes costs to job status
- **Cancel handling:** Subscribes to `job:{id}:control` channel, sends SIGTERM→SIGKILL
- **Secret redaction:** Strips API keys from output before Redis publish
- **Resume support:** Checks `job:{id}:resume` flag, finds session file, passes `--resume` to agent
- **Environment injection:** Passes 40+ env vars to the agent (phase, exploit mode, profile, freedom level, etc.)

**Finding normalization pipeline:**
```
Raw agent findings
  → _normalize_findings()     # Ensure title/severity/type
  → _map_severity()           # Impact text → severity level
  → _format_finding_description()  # Strip bash/JSON junk from descriptions
  → _coerce_evidence_strings()     # List → string conversion
  → _is_valid_credential()         # Reject garbage credentials (50+ garbage words)
  → POST /api/v1/jobs/{id}/findings  # Upsert with dedup
```

---

### 3. Kali Executor — The AI Agent

**Path:** `kali-executor/`  
**Core file:** `kali-executor/open-interpreter/dynamic_agent.py` — **6570 lines**, the brain of the entire system.

#### The Dynamic Agent (`DynamicAgent` class)

This is a fully autonomous penetration testing AI agent. It has **zero hardcoded exploit logic** — the LLM decides every action. The agent provides:

- A compact system prompt (~280 words) that defines the rules of engagement
- Skill injection from the 125-skill YAML library
- An execution loop that runs bash commands and feeds output back to the LLM
- 17+ automatic vulnerability detection patterns (regex-based, zero LLM cost)
- Artifact extraction (credentials, tokens, API keys, sessions) via regex
- Context summarization to stay within token limits
- Session persistence for resume capability
- Comprehensive reporting at completion

#### Agent Execution Loop

```
1. Build system prompt + skill context + phase policy
2. Send initial objective to LLM
3. FOR each iteration (up to max_iterations):
   a. Get LLM response → extract ```bash``` block
   b. Apply guard functions (scope check, command validation)
   c. Execute command in Kali container (subprocess)
   d. Capture stdout/stderr/exit_code/duration
   e. Auto-track vulnerabilities from output (17+ patterns)
   f. Extract artifacts to Arsenal (creds, tokens, keys)
   g. Feed result back to LLM as user message
   h. Check exploit gate (force exploitation of tracked vulns)
   i. Trim context if needed (digest summarization)
   j. Read supervisor hints (if any)
   k. Save session state for resume
4. Generate comprehensive report
5. Write findings.json, vuln_tracker.json, arsenal.json
```

#### Auto-Tracker: 17+ Vulnerability Types

The auto-tracker monitors every command execution's stdout/stderr and detects findings using pattern matching — **zero LLM tokens consumed**:

| # | Vulnerability Type | Detection Method |
|---|-------------------|------------------|
| 1 | **SQL Injection** | SQLi markers in curl + JWT returned, OR sqlmap confirms injection |
| 2 | **Path Traversal / LFI** | `../` in URL + `root:x:` in response |
| 3 | **Information Disclosure** | Exposed `.bak`/`.env`/`.sql` files with substantial content |
| 4 | **Mass Assignment** | `role=admin` in request + admin role reflected in response |
| 5 | **File Upload** | Risky file extensions (`.php`/`.jsp`/`.asp`) uploaded successfully |
| 6 | **Credentials in HTML** | HTML comments/source containing passwords or connection strings |
| 7 | **Default Credentials** | POST to login endpoint + success markers without fail markers |
| 8 | **Database Access** | Successful auth via mssqlclient/mysql/psql + DB prompt markers |
| 9 | **Remote Service Access** | SMB/RDP/WinRM auth success (crackmapexec, evil-winrm, etc.) |
| 10 | **Remote Code Execution** | Command execution on target + OS command output (uid=, whoami) |
| 11 | **Anonymous Access** | FTP anonymous login or SMB null session confirmed |
| 12 | **Privilege Escalation** | Privesc tools + system/root level confirmed |
| 13 | **Lateral Movement** | Cross-host movement via PsExec/WMI/pass-the-hash |
| 14 | **Persistence** | Scheduled tasks, registry keys, crontab, backdoor installation |
| 15 | **Credential Dumping** | secretsdump/mimikatz/hashdump with credential output |
| 16 | **Data Collection** | Database dumps, sensitive file reads with substantial content |
| 17 | **Data Exfiltration** | Data sent via curl/nc/SMB to external host |

**Additional detections:** Sensitive data via nmap scripts, XSS reflection, SSRF indicators, debug endpoint discovery.

#### Example: Auto-Tracker Pattern Matching

```python
def _auto_track_vulns_from_execution(self, execution: Execution) -> None:
    cmd_lower = cmd.lower()
    out_lower = out.lower()
    
    # SQLi via sqlmap
    if "sqlmap" in cmd_lower and execution.success:
        proof_markers = ("available databases", "database:", "table:",
                        "dumping", "retrieved", "entries")
        if any(m in out_lower for m in proof_markers):
            self._track_vuln_found("sql injection", target, evidence_snip)
    
    # Path traversal
    if "curl " in cmd_lower and ("../" in cmd_lower or "%2e%2e%2f" in cmd_lower):
        if "root:x:" in out_lower and "/bin/" in out_lower:
            self._track_vuln_found("path traversal", target, evidence_snip)
    
    # RCE confirmed
    rce_cmds = ("cmd=", "exec=", "shell=", "psexec", "wmiexec")
    if any(r in cmd_lower for r in rce_cmds):
        rce_output = ("nt authority", "uid=", "root", "whoami")
        if any(m in out_lower for m in rce_output):
            self._track_vuln_found("remote code execution", target, evidence_snip)
```

#### Arsenal System (Exploit Chain Memory)

The Arsenal automatically extracts and stores reusable artifacts from command output using compiled regex patterns:

```python
ARTIFACT_PATTERNS = {
    "credentials": [
        # JSON: {"username":"X","password":"Y"}
        re.compile(r'"(?:user(?:name)?)":\s*"([^"]+)".*?"(?:pass(?:word)?)":\s*"([^"]+)"'),
        # Colon-separated: username=admin password=secret
        re.compile(r'(?:username|user)[=:]\s*(\S+)[\s,;]+(?:password|pass)[=:]\s*(\S+)'),
    ],
    "tokens": [
        re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'),  # JWT
        re.compile(r'Bearer\s+([A-Za-z0-9_.\-]{20,})'),
    ],
    "api_keys": [
        re.compile(r'(AKIA[A-Z0-9]{16})'),  # AWS
        re.compile(r'(sk_(?:live|test)_[A-Za-z0-9]{24,})'),  # Stripe
    ],
    "sessions": [...],
    "secrets": [...]
}
```

Arsenal items survive context resets and session resumes, enabling the agent to chain exploits:
- Credential found at step 5 → used to authenticate at step 15
- JWT token extracted from SQLi → used for API access at step 20

#### Guard Functions

The agent enforces strict scoping and safety:

- **Scope validation:** Only attack targets in the allowed target list
- **Command sanitization:** Block commands targeting Docker internals / localhost
- **Tech-stack filtering:** Suppress impossible exploit classes (e.g., PHP exploits on Node.js targets)
- **Exploit gate:** Force exploitation of every tracked vulnerability before completion
- **Proof requirement:** High/critical severity requires concrete evidence; downgrades to medium otherwise
- **Redundant exploit blocking:** Prevents repeating the same exploit technique on the same vuln
- **Recon artifact rewrite protection:** Prevents overwriting scan results during exploit phase

#### Context Management

To stay within LLM token limits (25K for Claude, 20K for OpenAI, 131K for local models):

1. **Context trimming:** Oldest messages removed to stay under budget
2. **Digest summarization:** Rule-based extraction of services, vulns, credentials, commands, failures
3. **Digest merging:** New summaries deduplicated against existing digest
4. **Arsenal injection:** Credentials/tokens survive context resets
5. **Evidence injection:** Prior findings summarized and re-injected after supervisor resets

#### LLM Profile System

Profiles control agent behavior along a freedom spectrum:

| Profile | Freedom | Description |
|---------|---------|-------------|
| `strict` | 1-2 | Conservative, evidence-only, no creative exploitation |
| `balanced` | 3-5 | Default — exploit verified vulns, moderate creativity |
| `relaxed` | 6-7 | More aggressive, less restrictive scoping |
| `unleashed` | 8-9 | Full exploitation, persistence, defense evasion |
| `unhinged` | 10 | Maximum autonomy, no guardrails |

Controlled via `LLM_PROFILE` and `AGENT_FREEDOM` environment variables.

---

### 4. Supervisor

**Path:** `execution-plane/supervisor/main.py` (~1177 LOC)

The Supervisor monitors all active jobs via Redis pub/sub and intervenes when agents stall or loop:

#### Detection Heuristics

| Alert Type | Trigger | Action |
|------------|---------|--------|
| `stalled` | No output for 5 min (configurable) | LLM triage → hint injection |
| `noop_loop` | 3+ consecutive no-op commands (sleep, date, pwd) | Context reset suggestion |
| `repeated_command` | Same command repeated 2+ times | Directive to try alternative |
| `no_new_findings` | 15+ min without new findings | Escalation prompt |
| `scan_loop` | >70% enum commands in last 20 cmds, with <30% exploit | "Pivot to exploitation" hint |

#### LLM-Augmented Triage

When an alert fires, the Supervisor can optionally query the LLM to generate targeted advice:

```python
# Supervisor → Internal LLM Proxy → Response
# Response written to: /pentest/output/{job_id}/supervisor_hints.jsonl
# Dynamic agent reads hints at each iteration
```

#### Supervisor Actions

- **Hint injection:** Write JSONL directive to shared volume → agent reads on next iteration
- **Context reset:** Signal the agent to rebuild its conversation from scratch
- **Dry-run mode:** Log actions without executing (for tuning)
- **Per-job overrides:** Enable/disable supervisor per job via Redis keys
- **Cooldowns:** Configurable per-alert and per-job action limits

#### Command Classification

```python
ENUM_COMMAND_MARKERS = ["nmap", "masscan", "gobuster", "dirb", "ffuf",
                        "nikto", "whatweb", "nuclei", "amass", ...]

EXPLOIT_COMMAND_MARKERS = ["sqlmap", "commix", "msfconsole", "hydra",
                           "medusa", "hashcat", "crackmapexec", ...]
```

The supervisor classifies every command as `exploit | enum | other` and tracks the ratio to detect scan loops.

---

### 5. Frontend — Next.js Dashboard

**Path:** `frontend/`  
**Key pages:**

| Page | Path | Lines | Purpose |
|------|------|-------|---------|
| Dashboard | `src/app/page.tsx` | ~262 | Overview: running jobs, recent findings, stats |
| Pentest List | `src/app/pentests/page.tsx` | — | All jobs with filters |
| **Pentest Detail** | `src/app/pentests/[id]/page.tsx` | ~1802 | The main view — live output, findings, loot |
| Reports | `src/app/reports/page.tsx` | — | Generated pentest reports |
| Settings | `src/app/settings/page.tsx` | — | LLM providers, tenant config |
| Agents | `src/app/agents/page.tsx` | — | Agent status and configuration |
| Terminal | `src/app/terminal/[sessionId]/page.tsx` | — | Interactive terminal sessions |

#### Live Intelligence Panel (`pentests/[id]/page.tsx`)

The crown jewel of the frontend. Polls `/api/v1/jobs/{id}/live-intel` and displays:

- **Ports & Services:** Parsed from nmap output, sorted by port
- **Tech Stack:** WhatWeb fingerprints, headers, runtime detection
- **Web Paths:** Gobuster/ffuf results with HTTP status codes
- **ExploitDB Matches:** Searchsploit results (JSON + text parsing)
- **Vulnerability Tracker:** Real-time vuln status (unproven → attempted → proven)
- **Exploitation Timeline:** Attempts sorted by iteration with success/fail indicators
- **Credentials Found:** From Arsenal, masked by default with reveal toggle
- **Access Level:** Derived from exploitation evidence (user → admin → SYSTEM)
- **Live Terminal Output:** WebSocket-streamed agent output with ANSI rendering
- **Findings Feed:** Severity-tagged finding cards with evidence snippets
- **Loot Table:** Extracted credentials, hashes, tokens, configs, DB samples
- **Progress Ring:** Visual iteration counter with percentage
- **Dopamine Feed:** Real-time feed of interesting events (vulns found, creds extracted)

**Features:**
- Secret redaction in the UI (API keys, Bearer tokens, Zhipu keys)
- Noisy SDK log line filtering (httpcore, httpx debug lines)
- Auto-scroll with manual override
- Job control: Cancel, Resume buttons
- Report generation and download

---

### 6. Skills Engine

**Path:** `skills/`  
**125 skills** across 11+ categories, each defined by a `SKILL.md` methodology document and a `skill.yaml` metadata file.

#### Skill Structure

```
skills/
├── skill_loader.py       # SkillLoader class — discovers & parses all skills
├── skill_router.py       # SkillRouter class — phase-based skill selection
├── SKILL_CATALOG.json    # Generated catalog of all skills
├── reconnaissance/       # Example skill directory
│   ├── SKILL.md          # Methodology document (injected into AI prompt)
│   └── skill.yaml        # Metadata: phase, MITRE techniques, tools, etc.
├── sql_injection/
│   ├── SKILL.md
│   └── skill.yaml
├── tool_nmap/
│   ├── SKILL.md
│   ├── skill.yaml
│   └── tools.yaml        # Optional: tool definitions with install/verify commands
└── ... (125 total)
```

#### `skill.yaml` Format

```yaml
id: sql_injection
name: SQL Injection
category: exploitation
phase: EXPLOIT
priority: 80
target_types: [lab, external]
description: Detect and exploit SQL injection vulnerabilities.
mitre_techniques: [T1190]
inputs: [vulns.json]
outputs: [evidence.json, findings.json, creds.json]
prerequisites: [vulns]
success_criteria:
  - SQL injection confirmed
  - Data extracted with evidence
safety_notes:
  - Minimize data extracted to verify impact
```

#### Skill Categories (by count)

| Category | Skills | Example Skills |
|----------|--------|----------------|
| Post-Exploit | 37 | credential_access, privilege_escalation, lateral_movement, persistence, defense_evasion, collection, exfiltration, impact |
| Tools | 36 | tool_nmap, tool_sqlmap, tool_hydra, tool_gobuster, tool_ffuf, tool_burp, tool_hashcat |
| Service-Specific | 20+ | ssh, smb, ftp, mysql, postgres, mssql, redis, mongodb, ldap, rdp, imap, smtp, pop3, snmp, dns |
| Reconnaissance | 19 | reconnaissance, scanning, discovery |
| Vulnerability Scanning | 15 | scanning, app_security, xss, sql_injection |
| Exploitation | 14 | exploitation, reverse_engineering |
| Cloud/Container | 6 | aws, azure, gcp, docker, kubernetes |
| Other | 10+ | active_directory, wireless, vpn, reporting, forensics, cicd |

#### Skill Router (`SkillRouter`)

Phase-to-category mapping determines which skills are eligible:

```python
DEFAULT_PHASE_CATEGORY_MAP = {
    "RECON":        ["reconnaissance"],
    "VULN_SCAN":    ["scanning"],
    "EXPLOIT":      ["exploitation"],
    "LATERAL":      ["credential_access", "privilege_escalation", "lateral_movement",
                     "persistence", "defense_evasion", "discovery", "collection",
                     "exfiltration", "impact", "analysis"],
    "FULL":         [...all categories...],
    "POST_EXPLOIT": [...same as LATERAL...],
    "REPORT":       ["reporting"],
}
```

Selection logic:
1. Filter by `target_type` compatibility (lab/external)
2. Check prerequisites against available evidence
3. Match service hints against skill tags (e.g., "mysql" → mysql skill)
4. Sort by priority (descending), select top N (default: 3)
5. Service-specific skills get priority when service hints exist

---

### 7. LLM Pipeline

```
┌─────────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│  Kali Container  │     │  Control Plane API   │     │  LLM Provider    │
│  llm_client.py   │────▶│  /api/internal/llm/  │────▶│  (Claude, GLM,   │
│                  │     │  chat                │     │   OpenAI, etc.)  │
│  LLM_PROXY_URL   │     │                     │     │                  │
│  LLM_PROXY_TOKEN │     │  Provider routing    │     │                  │
│                  │◀────│  Retry + backoff     │◀────│                  │
│  Parse response  │     │  Thinking support    │     │                  │
│  Track tokens    │     │  Secret management   │     │                  │
└─────────────────┘     └─────────────────────┘     └──────────────────┘
```

#### LLM Client (`kali-executor/open-interpreter/llm_client.py`, ~813 LOC)

Handles all LLM communication from inside the Kali container:

- **Proxy mode** (recommended): POST to `LLM_PROXY_URL` — keys never touch the container
- **Direct mode:** Direct API calls to Claude/OpenAI/Zhipu/local with provider-specific handling
- **Hard timeout:** SIGALRM-based wall-clock timeout (survives DNS hangs)
- **Cost tracking:** Per-model pricing table (40+ models) with per-interaction cost calculation
- **Context trimming:** 25K tokens for Claude, 20K for OpenAI, 131K for local
- **Token logging:** Every interaction logged to `llm_interactions.jsonl` with full I/O

#### Pricing Coverage

The LLM client tracks costs for 40+ models including:

```
Claude Opus 4.6, Sonnet 4.5/4, Haiku 3.5/3
GPT-5.2 (Codex/Pro), 5.1, 5, 4.1 (Mini/Nano), 4o (Mini), o4/o3/o1
GLM-5, 4.7 (Flash), 4.6, 4.5
Kimi K2.5, K2 (Thinking/Turbo)
DeepSeek R1, V3.2, V3.1, V3
Qwen3 Coder, Max, 235B
Gemini 3 Pro/Flash, 2.5 Flash
MiniMax M2.1/M2
Grok, Llama 3.3/4 Maverick
```

#### Thinking/Reasoning Support

When `LLM_THINKING_ENABLED=true`:
- Proxy injects `thinking: {type: "enabled"}` into request payload
- GLM-5 returns `reasoning_content` alongside regular `content`
- Claude uses native extended thinking when supported
- Thinking directives mapped to 5 levels (minimal → xhigh) injected into system prompt

---

## Data Flow

### Job Lifecycle: Creation → Findings

```
USER clicks "New Pentest" in Frontend
    │
    ▼
POST /api/v1/jobs → API validates scope, targets, exploit_mode, quotas
    │
    ▼
Job record → PostgreSQL (status: pending)
AuditLog record → PostgreSQL
LPUSH → Redis: tenant:{id}:job_queue
    │
    ▼
Scheduler BRPOP → tenant:{id}:job_queue
    │ (checks MAX_CONCURRENT_JOBS)
    ▼
LPUSH → Redis: worker:job_queue
    │
    ▼
Worker BRPOP → worker:job_queue
    │
    ├── GET /api/v1/jobs/{id} → fetch job details
    ├── Find available Kali container (Docker SDK)
    ├── PATCH /api/v1/jobs/{id} → status: running
    │
    ▼
docker exec → Kali container:
    python3 /opt/tazosploit/dynamic_agent.py \
      --target 10.0.0.5 \
      --objective "Complete penetration test of 10.0.0.5" \
      --max-iterations 30 \
      --output-dir /pentest/output/{job_id}
    │
    ▼
Agent iterates (up to max_iterations):
    │
    ├── LLM request → Proxy → Provider → Response
    ├── Extract ```bash``` → Execute command
    ├── Auto-tracker scans stdout for vulns ────────┐
    ├── Arsenal extracts creds/tokens ──────────────┤
    ├── [REMEMBER:] tags → Memory store             │
    ├── Output line → Redis pub/sub ─────────────── │ ──→ Frontend (WebSocket)
    │                                                │
    │  (every 30 seconds)                            │
    ├── Worker reads vuln_tracker.json ◄─────────────┘
    ├── POST /api/v1/jobs/{id}/findings → upsert
    ├── POST /api/v1/loot → credentials, tokens
    └── PATCH /api/v1/jobs/{id} → token counts
    │
    ▼
Agent writes final output:
    /pentest/output/{job_id}/
    ├── agent_report_*.json         # Full structured report
    ├── vuln_tracker.json           # All tracked vulns + proof status
    ├── arsenal.json                # Extracted creds/tokens/keys
    ├── session_*.json              # Session state (for resume)
    ├── context_digest.md           # Summarized context
    ├── handoff.json                # Session handoff instructions
    ├── mitre_coverage.json         # MITRE technique coverage
    ├── tech_fingerprint.json       # Tech stack detection
    ├── COMPREHENSIVE_REPORT_*.md   # Human-readable report
    └── evidence/
        ├── findings.json           # Structured findings
        ├── credentials.json        # Extracted credentials
        └── *.txt, *.json           # Tool-specific evidence
    │
    ▼
Worker reads results:
    ├── POST /api/v1/jobs/{id}/findings → final finding push
    ├── POST /api/v1/loot → final loot push
    ├── PATCH /api/v1/jobs/{id} → status: completed, result JSON
    └── Redis SET job:{id}:terminal → "completed"
    │
    ▼
Frontend polls /api/v1/jobs/{id} → updates dashboard
Frontend polls /api/v1/jobs/{id}/live-intel → updates Live Intelligence
Frontend receives WebSocket → live terminal output
```

### Supervisor Data Flow (Parallel)

```
Supervisor subscribes → Redis: job:*:output
    │
    ├── Parse log lines for iteration/command/timing
    ├── Track per-job state (commands, findings, timing)
    ├── Detect: stall, noop_loop, scan_loop, repeated_command
    │
    ▼ (on alert)
    ├── Optional: LLM triage call → Internal Proxy
    ├── Write hint → /pentest/output/{job_id}/supervisor_hints.jsonl
    └── Agent reads hint on next iteration → adjusts behavior
```

---

## Kill Chain Coverage

TazoSploit maps to **11 MITRE ATT&CK phases** through its 125-skill library:

| Phase | MITRE Tactics | Skills | Key Capabilities |
|-------|--------------|--------|-------------------|
| **Reconnaissance** | TA0043 | 19 | nmap, masscan, amass, subfinder, theharvester, whatweb, gobuster |
| **Resource Development** | TA0042 | — | Wordlist generation (cewl, crunch), payload creation |
| **Initial Access** | TA0001 | 14 | SQLi, XSS, SSRF, file upload, default creds, phishing |
| **Execution** | TA0002 | — | Command injection, code execution, msfconsole |
| **Persistence** | TA0003 | 4+ | Crontab, registry, services, webshells, backdoors |
| **Privilege Escalation** | TA0004 | 8+ | SUID, sudo, token impersonation, kernel exploits |
| **Defense Evasion** | TA0005 | 5+ | Proxychains, TOR, macchanger, log clearing |
| **Credential Access** | TA0006 | 10+ | Hydra, hashcat, john, mimikatz, secretsdump |
| **Discovery** | TA0007 | 10+ | Port scanning, service enum, AD recon, network mapping |
| **Lateral Movement** | TA0008 | 8+ | PsExec, WMI, pass-the-hash, SMB, SSH pivoting |
| **Collection** | TA0009 | 5+ | Database dumps, file collection, keylogging |
| **Exfiltration** | TA0010 | 3+ | DNS tunneling, HTTP upload, SMB transfer |
| **Impact** | TA0040 | 2+ | Data destruction, ransomware simulation |

### Kali Container Toolchain (150+ tools)

The Kali executor Dockerfile installs tools across all categories:

```
RECONNAISSANCE:  nmap, masscan, unicornscan, dnsrecon, dnsenum, fierce,
                 subfinder, amass, sublist3r, theharvester, recon-ng,
                 whatweb, wafw00f, whois, dmitry

VULN SCANNING:   nikto, wpscan, joomscan, sqlmap, commix, sslscan,
                 sslyze, wfuzz, ffuf, gobuster, dirb, nuclei

EXPLOITATION:    metasploit-framework, burpsuite, zaproxy, responder,
                 bettercap, ettercap, exploitdb, aircrack-ng, wifite,
                 hydra, medusa, ncrack, crowbar, patator

POST-EXPLOIT:    crackmapexec, evil-winrm, smbclient, impacket-scripts,
                 weevely

CREDENTIALS:     john, hashcat, hash-identifier, cewl, crunch, cupp

FORENSICS:       sleuthkit, foremost, scalpel, testdisk, wireshark,
                 tcpdump, tshark, yara, clamav, radare2, binwalk

UTILITY:         netcat, ncat, socat, proxychains4, tor, jq, xmlstarlet

PYTHON:          pwntools, impacket, scapy, paramiko, requests,
                 beautifulsoup4, httpx, aiohttp, litellm, anthropic

GITHUB TOOLS:    PEASS-ng (linpeas/winpeas), LaZagne, wesng,
                 linux-exploit-suggester, SecLists, PayloadsAllTheThings
```

---

## Configuration

### Environment Variables

#### LLM Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `anthropic` | Default LLM provider |
| `LLM_MODEL` | `claude-sonnet-4-5-20250514` | Default model |
| `LLM_API_BASE` | `https://api.anthropic.com` | API endpoint |
| `LLM_PROXY_TOKEN` | — | Shared token for internal LLM proxy auth |
| `LLM_PROXY_URL` | `http://api:8000/api/internal/llm/chat` | Proxy endpoint (set in Kali container) |
| `LLM_THINKING_ENABLED` | `false` | Enable reasoning/thinking support |
| `LLM_PROXY_TIMEOUT_SECONDS` | `120` | Request timeout for proxy |
| `LLM_PROXY_RETRY_MAX` | `5` | Max retry attempts |
| `LLM_PROXY_RETRY_BASE_SECONDS` | `2` | Base backoff for retries |
| `LLM_HARD_TIMEOUT_SECONDS` | `300` | SIGALRM hard timeout |
| `LLM_CONTEXT_WINDOW` | `131072` | Max context window tokens |
| `LLM_MAX_TOKENS` | `4096` | Max completion tokens |
| `ANTHROPIC_API_KEY` | — | Claude API key |
| `ANTHROPIC_TOKEN` | — | Claude subscription/OAuth token |
| `ZHIPU_API_KEY` | — | GLM/Z.AI API key |

#### Execution Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONCURRENT_JOBS` | `10` | Max simultaneous jobs |
| `DEFAULT_JOB_TIMEOUT` | `3600` | Job timeout in seconds |
| `EXPLOIT_MODE` | `explicit_only` | `disabled` / `explicit_only` / `autonomous` |
| `LLM_PROFILE` | — | Agent profile: strict/balanced/relaxed/unleashed/unhinged |
| `AGENT_FREEDOM` | — | Freedom level 1-10 |
| `ALLOW_PERSISTENCE` | `false` | Allow persistence mechanisms |
| `ALLOW_DEFENSE_EVASION` | `false` | Allow defense evasion techniques |
| `ALLOW_SCOPE_EXPANSION` | `false` | Allow scanning beyond initial targets |
| `ENABLE_TARGET_ROTATION` | `true` | Rotate between in-scope targets |

#### Supervisor Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SUPERVISOR_LLM_MODE` | `stub` | `disabled` / `stub` / `live` |
| `SUPERVISOR_LLM_PROVIDER` | `anthropic` | Provider for supervisor triage calls |
| `SUPERVISOR_ALERT_STALL_SECONDS` | `300` | Seconds before stall alert |
| `SUPERVISOR_ALERT_NOOP_THRESHOLD` | `3` | Consecutive no-ops before alert |
| `SUPERVISOR_FINDINGS_STALL_SECONDS` | `900` | Seconds without findings before alert |
| `SUPERVISOR_SCAN_LOOP_WINDOW` | `20` | Commands to analyze for scan loop |
| `SUPERVISOR_SCAN_LOOP_ENUM_RATIO` | `0.7` | Enum/total ratio to trigger scan_loop |
| `SUPERVISOR_ACTIONS_ENABLED` | `true` | Enable supervisor interventions |
| `SUPERVISOR_ACTION_MAX_PER_JOB` | `5` | Max interventions per job |

#### Database & Infrastructure

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `DB_PASSWORD` | (change in production) | Database password |
| `SECRET_KEY` | — | JWT signing key |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:3001` | Allowed CORS origins |
| `LOG_LEVEL` | `DEBUG` | Logging verbosity |

### Docker Setup

```bash
# Start the full platform
docker compose up -d

# Start vulnerable lab targets (separate lifecycle)
docker compose -f docker-compose.lab.yml up -d

# Tear down
docker compose down -v
```

**Resource limits (per Kali container):**
- CPU: 2 cores (0.5 reserved)
- Memory: 4GB (1GB reserved)
- tmpfs: 1GB at /tmp, 100MB at /run
- Security: `no-new-privileges`, `NET_RAW` capability only

---

## Key Design Decisions

### 1. LLM Proxy Architecture

**Decision:** Route all LLM calls through an internal proxy (`/api/internal/llm/chat`) rather than embedding API keys in executor containers.

**Why:**
- **Security:** API keys never touch the Kali container filesystem or environment
- **Centralization:** Single point for retry logic, rate limiting, provider switching
- **Multi-provider:** Swap providers without rebuilding containers
- **Cost tracking:** Centralized token accounting
- **Thinking support:** Inject thinking directives at the proxy layer

### 2. Zero Hardcoded Exploits

**Decision:** The agent has no built-in exploit scripts. The LLM decides every action.

**Why:**
- Adapts to any target (web, network, IoT, cloud)
- New vulnerabilities don't require code changes
- Skills provide methodology, not implementation
- The LLM can combine tools creatively (e.g., chain sqlmap output into curl)

### 3. Auto-Tracker (Regex-Based Vuln Detection)

**Decision:** Detect vulnerabilities from command output using regex patterns instead of asking the LLM to classify findings.

**Why:**
- **Zero token cost:** Regex runs locally, no LLM call needed
- **Reliability:** LLMs inconsistently emit `[REMEMBER:]` tags
- **Speed:** Instant detection vs. waiting for LLM response
- **Coverage:** 17+ patterns cover the most common finding types
- **Defense in depth:** Auto-tracker catches what the LLM misses

### 4. Skill YAML Format

**Decision:** Skills are directories with `SKILL.md` (methodology) + `skill.yaml` (metadata) rather than executable scripts.

**Why:**
- **Prompt injection:** Methodology text is injected into the LLM context, guiding behavior without constraining it
- **Extensibility:** Add a new skill = create a directory with two files
- **No code execution risk:** Skills are documentation, not runnable code
- **Phase routing:** YAML metadata enables automatic skill selection per job phase

### 5. Guard Functions & Exploit Gate

**Decision:** Force the agent to attempt exploitation of every tracked vulnerability before completing.

**Why:**
- LLMs tend to over-enumerate and under-exploit
- Without the gate, agents often do 30 iterations of nmap/gobuster without trying a single exploit
- The gate ensures findings are proven, not just detected
- Proof requirement prevents false positives in severity ratings

### 6. Context Digest Summarization

**Decision:** Use rule-based regex extraction instead of LLM-based summarization for context management.

**Why:**
- **Cost reduction:** Previously used ~512 tokens per trim cycle; regex costs zero
- **Equivalent quality:** Rule-based extraction captures services, credentials, vulns, commands
- **Deterministic:** Same input → same output (no LLM variability)
- **Resilient:** Works even when the LLM proxy is rate-limited or down

### 7. Multi-Network Docker Isolation

**Decision:** Four separate Docker networks with minimal cross-connectivity.

**Why:**
- **Control-net:** API/DB/Redis can't reach lab targets directly
- **Exec-net:** Workers can reach Redis but not Postgres
- **Kali-net:** Executors can reach lab targets and internet (for LLM API) but not Postgres
- **Lab-net:** External network for vulnerable targets, fully isolated from control plane

### 8. DOM Renderer (Headless Browser)

**Decision:** Dedicated Playwright container for rendering JavaScript-heavy targets.

**Why:**
- Many modern web apps require JS execution to enumerate endpoints
- curl/wget miss client-side rendered content
- Separate container isolates browser attack surface
- Agent can request DOM snapshots via `DOM_RENDERER_URL`

---

## File Map

### Control Plane (`control-plane/`)

| File | Lines | Purpose |
|------|-------|---------|
| `Dockerfile` | ~35 | Python 3.11-slim, pip install, non-root user |
| `api/__init__.py` | 1 | Package marker |
| `api/models.py` | ~708 | SQLAlchemy ORM: 10 models (Tenant, User, Scope, Job, Finding, AuditLog, Policy, Loot, ScheduledJob, Workspace) |
| `api/database.py` | ~48 | AsyncSession factory, engine config |
| `api/auth.py` | ~110 | JWT decode, role checks, internal auth |
| `api/utils/redact.py` | — | Secret redaction patterns |
| `api/utils/crypto.py` | — | AES encrypt/decrypt for tenant keys |
| `api/routers/jobs.py` | ~1619 | Job CRUD, findings, live-intel, logs, output |
| `api/routers/internal_llm.py` | ~591 | LLM proxy with 20+ providers |
| `api/routers/websocket.py` | ~358 | WebSocket output streaming |
| `api/routers/auth_router.py` | — | Login, register, token refresh |
| `api/routers/scopes.py` | — | Target scope management |
| `api/routers/tenants.py` | — | Tenant CRUD |
| `api/routers/settings.py` | — | Platform settings, LLM config |
| `api/routers/dashboard.py` | — | Dashboard aggregation |
| `api/routers/loot.py` | — | Loot/evidence management |
| `api/routers/reports.py` | — | Report generation |
| `api/routers/audit.py` | — | Audit log queries |
| `api/routers/mitre.py` | — | MITRE ATT&CK mapping |
| `api/routers/policies.py` | — | Execution policies |
| `api/routers/attack_graphs.py` | — | Attack graph visualization |
| `api/routers/terminal.py` | — | Terminal session management |
| `api/routers/agents.py` | — | Agent status |
| `api/routers/scheduled_jobs.py` | — | Cron-style job scheduling |
| `api/routers/simulations.py` | — | Attack simulations |
| `api/routers/workspaces.py` | — | Workspace management |
| `db/init.sql` | ~470 | Schema DDL, indexes, seed data |

### Execution Plane (`execution-plane/`)

| File | Lines | Purpose |
|------|-------|---------|
| `scheduler/main.py` | ~167 | Job queue distribution, slot management |
| `worker/main.py` | ~1628 | Container exec, finding push, loot, streaming |
| `supervisor/main.py` | ~1177 | Stall detection, LLM triage, hint injection |

### Kali Executor (`kali-executor/`)

| File | Lines | Purpose |
|------|-------|---------|
| `Dockerfile` | ~200 | Kali Rolling, 150+ tools, Python libs, SecLists |
| `open-interpreter/dynamic_agent.py` | **~6570** | **The brain:** Agent loop, auto-tracker, arsenal, guards, digest |
| `open-interpreter/llm_client.py` | ~813 | LLM communication, retry, cost tracking, 40+ model pricing |
| `open-interpreter/llm_profiles.py` | — | Profile system (strict → unhinged) |
| `open-interpreter/llm_providers.py` | — | Multi-provider abstraction |
| `open-interpreter/comprehensive_report.py` | — | Markdown report generation |
| `open-interpreter/memory.py` | — | Persistent memory store |
| `open-interpreter/cve_lookup.py` | — | CVE database queries |
| `open-interpreter/config.py` | — | Agent configuration |
| `open-interpreter/agent_wrapper.py` | — | Legacy wrapper (deprecated) |
| `open-interpreter/tools/websearch.py` | — | Web search helper |
| `open-interpreter/tools/docslookup.py` | — | Documentation lookup |
| `open-interpreter/tools/download.py` | — | File download helper |

### Skills (`skills/`)

| File | Lines | Purpose |
|------|-------|---------|
| `skill_loader.py` | ~331 | Discovers skills, parses SKILL.md + skill.yaml |
| `skill_router.py` | ~171 | Phase → category mapping, skill selection |
| `SKILL_CATALOG.json` | — | Generated catalog of all 125 skills |
| `SKILL_TEMPLATE.md` | — | Template for creating new skills |
| `125 skill directories` | — | Each with SKILL.md + skill.yaml (+ optional tools.yaml) |

### Frontend (`frontend/`)

| File | Lines | Purpose |
|------|-------|---------|
| `Dockerfile` | — | Next.js build + serve |
| `src/app/page.tsx` | ~262 | Dashboard |
| `src/app/pentests/[id]/page.tsx` | ~1802 | **Main pentest view** — live intel, terminal, findings |
| `src/app/pentests/page.tsx` | — | Pentest list |
| `src/app/reports/page.tsx` | — | Report viewer |
| `src/app/settings/page.tsx` | — | Settings |
| `src/app/agents/page.tsx` | — | Agent management |
| `src/app/terminal/[sessionId]/page.tsx` | — | Interactive terminal |
| `src/components/DopamineFeed.tsx` | — | Real-time event feed |
| `src/components/ProgressRing.tsx` | — | Visual progress indicator |
| `src/components/Card.tsx` | — | Reusable UI components |
| `src/lib/api.ts` | — | API client |
| `src/lib/utils.ts` | — | Utility functions |

### Infrastructure

| File | Lines | Purpose |
|------|-------|---------|
| `docker-compose.yml` | ~300 | Main platform (11 services) |
| `docker-compose.lab.yml` | — | Vulnerable lab targets |
| `.env` | ~50 | Environment configuration |
| `dom-renderer/server.py` | — | Playwright DOM rendering service |
| `dom-renderer/Dockerfile` | ~12 | Playwright Python image |
| `tunnel-gateway/main.go` | — | WireGuard VPN gateway |
| `tunnel-gateway/api.go` | — | VPN management API |
| `tunnel-gateway/wg.go` | — | WireGuard interface management |
| `tunnel-gateway/Dockerfile` | ~25 | Go builder + Alpine runtime |

---

## Database Schema

PostgreSQL 15 with 10 tables:

```
tenants          → Multi-tenant organizations (tier, limits, API keys)
users            → Tenant members (email, role, MFA)
scopes           → Authorized target scopes (targets, excluded, time windows)
jobs             → Pentest job execution (phase, status, results, costs)
findings         → Discovered vulnerabilities (severity, evidence, MITRE)
audit_logs       → Immutable audit trail (who/what/when)
policies         → Execution policies (restrict phases, tools, targets)
loot             → Extracted credentials, tokens, configs
scheduled_jobs   → Cron-style recurring jobs
workspaces       → Shared workspaces across tenants
```

**Key relationships:**
```
Tenant ─┬─▶ Users
        ├─▶ Scopes ──▶ Jobs ──▶ Findings
        ├─▶ Policies         ──▶ Loot
        └─▶ AuditLogs
```

---

## Contributing

To add a new skill:

```bash
mkdir skills/my_new_skill
# Create SKILL.md with methodology
# Create skill.yaml with metadata (see SKILL_TEMPLATE.md)
# Restart Kali container — skills are mounted read-only via Docker volume
```

To add a new LLM provider:
1. Add provider base URL to `DEFAULT_PROVIDER_BASES` in `internal_llm.py`
2. Add model prefix aliases to `MODEL_PREFIX_ALIASES`
3. Add pricing to `_calculate_cost()` in `llm_client.py`

---

*Last updated: 2026-02-12 | TazoSploit v2*
