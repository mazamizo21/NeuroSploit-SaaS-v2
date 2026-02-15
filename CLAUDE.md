# TazoSploit — AI-Powered Pentest SaaS

## Project Overview
AI-driven autonomous penetration testing platform. LLM agents execute real attacks against targets using Kali Linux containers.

## Architecture
- **API/Orchestrator**: FastAPI (`main.py`) — job management, Redis state, WebSocket status
- **Dynamic Agent**: `kali-executor/open-interpreter/dynamic_agent.py` (~9300 lines) — core LLM attack loop
- **Supervisor**: `execution-plane/supervisor/main.py` (~1200 lines) — monitors agent, escalates stuck behavior
- **Skill System**: 125+ skills in `skills/`, MITRE ATT&CK mapped (265 IDs, 11 phases)
- **LLM Client**: `llm_client.py` — multi-provider (OpenAI, Anthropic, Google, local models)
- **Docker**: Kali containers with full pentest toolkits, Redis for state, NFS shared output

## Key Files
- `dynamic_agent.py` — THE file. Agent loop, evidence detection, vuln tracking, exploit gate, phase management
- `supervisor/main.py` — Escalation ladder, intervention actions, health monitoring
- `skill_loader.py` / `skill_router.py` — Dynamic skill selection based on target + phase
- `models.py` — Pydantic models for jobs, findings, scopes
- `tests/unit/` — Pytest suite (55+ tests)

## Known Issues & Recent Fixes (2026-02-15)
1. **Supervisor escalation**: Fixed — was falling through to global `false` on Redis transient errors
2. **Exploit gate death loop**: Fixed — vulns now marked `not_exploitable_reason` before pivot
3. **False evidence detection**: Fixed — HTML comments, tags, tool banners now stripped before pattern matching
4. **Discovery-vs-Exploitation gap**: Architectural issue — agent prefers scanning over real exploitation. Needs proactive phase forcing.

## Development Rules
- Python 3.14 venv at `./venv/bin/python`
- Tests: `./venv/bin/python -m pytest tests/unit/ -v --tb=short`
- Docker rebuild after code changes: `docker compose build kali-executor-1 kali-executor-2`
- Impacket fix is ephemeral — re-apply `sed` on mssqlclient.py line 93 after container restart
- Network routes to 192.168.4.0/24 are ephemeral — re-add after container restart

## Coding Standards
- Always run full test suite after changes
- Log extensively — every decision point should emit a log line
- Never hardcode targets — everything via API `run(target, objective)` and env vars
- Evidence patterns need source validation (HTML stripping, banner detection)

@README.md
