# TazoSploit — AI-Powered Penetration Testing Platform

## Quick Start (One Click!)

```bash
# Start the full platform
docker compose up -d

# That's it. Visit http://localhost:3000
```

## Security Hardening (Recommended)

If you run untrusted jobs/tenants, do **not** place provider API keys inside the Kali executor container.
Use the internal LLM proxy + hardened overrides:

```bash
# 1) Set a strong token in .env
#    LLM_PROXY_TOKEN=<long-random-string>

# 2) Start with hardened overrides
docker compose -f docker-compose.yml -f docker-compose.secure.yml up -d
```

This keeps provider keys in the control-plane only, and adds defense-in-depth redaction for job output.

**Login:** `admin@tazosploit.local` / `admin123`

## What You Get

| Service | URL | Purpose |
|---------|-----|---------|
| Frontend | http://localhost:3000 | Web GUI |
| API | http://localhost:8000 | REST API + Swagger at /api/docs |
| MinIO Console | http://localhost:9001 | Evidence storage |

### Core Stack (10 containers)
- **PostgreSQL** — Job & tenant database
- **Redis** — Queue & pub/sub
- **MinIO** — Evidence/loot storage
- **API** — FastAPI control plane
- **Frontend** — Next.js dashboard
- **Scheduler** — Job dispatch
- **Workers (x2)** — Job execution
- **Kali (x2)** — Pentest tools + AI agent

## Exploit Proof Gate (Required)

TazoSploit runs in an **evidence-first** mode by default: a vulnerability is not considered exploited unless the agent captures **proof** from a real command execution (or artifact).

Where it lives:
- `/Users/tazjack/Documents/PenTest/TazoSploit/kali-executor/open-interpreter/dynamic_agent.py`

What counts as proof (examples):
- SQLi: `sqlmap --dump` output showing actual dump markers, or an auth-bypass request that returns a JWT and indicates privileged access.
- LFI/Traversal: `/etc/passwd`-like content (e.g. `root:x:`) or multiple secret markers.
- RCE / command injection: requires `uid=` output (not just `whoami`).
- File upload/webshell: upload success is NOT proof; must show execution evidence (`uid=` or `root:x:`).
 
Proof capture behavior:
- Proof is stored as `cmd: ...` + `output: ...` (JWTs/passwords are redacted in the saved proof snippet).
- Curl progress-meter noise is stripped from saved evidence/proof so findings don’t show `% Total ...` blocks.
- Exposed backup files (e.g. `/ftp/*.bak`) are auto-tracked as `information disclosure` and can be proven by successfully retrieving non-trivial file contents.

Security controls evidence:
- When responses indicate blocking/throttling/quarantine (WAF/AV/IDS/XDR), the agent logs a redacted event stream to `evidence/security_controls.jsonl`.
- Reports also include a “Security Controls Observed” section when events exist.

Key env toggles:
- `ENFORCE_EXPLOITATION_PROOF` (default: `true`)
- `EXPLOITATION_PROOF_MAX_ATTEMPTS_PER_VULN`
- `EXPLOITATION_PROOF_FAIL_MODE` (`stop` or `skip`)

## Supervisor Agent (Watch And Fix)

The supervisor runs as a separate service (`tazosploit-supervisor`) and watches worker output via Redis pub/sub + `job:*:live_stats`. When it detects stalls/loops, it can inject hints into the running Kali container (`/pentest/output/<job_id>/supervisor_hints.jsonl`).

Why separate LLMs:
- Main attack agent can stay on a cheaper/faster model (e.g. GLM 4.7).
- Supervisor can be a different model to reduce shared blind spots.

Switch supervisor LLM temporarily (keep Claude configured):
- `.env` supports a reversible override:
  - `SUPERVISOR_LLM_PROVIDER_OVERRIDE=zai`
  - `# SUPERVISOR_LLM_PROVIDER_OVERRIDE=anthropic` (commented for quick revert)

Operational hardening:
- Supervisor timeout default is `90s` (provider calls can be slow).
- If the LLM proxy is rate-limited (429) or transiently failing, the supervisor falls back to stub decisions instead of failing audits.

## Running A Lab Job Via API

Internal auth token:
```bash
SECRET=$(grep '^SECRET_KEY=' .env | cut -d= -f2-)
AUTH="Authorization: Bearer internal-$SECRET"
```

Create a FULL autonomous Juice Shop run (example):
```bash
curl -s -X POST http://localhost:8000/api/v1/jobs \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{
    "name":"Juice Shop FULL",
    "scope_id":"<SCOPE_ID>",
    "phase":"FULL",
    "targets":["juiceshop"],
    "target_type":"lab",
    "exploit_mode":"autonomous",
    "timeout_seconds":108000,
    "max_iterations":3000,
    "llm_provider":"zai",
    "supervisor_enabled":true,
    "supervisor_provider":"zai"
  }'
```

### Kali Executor Tools
Nmap, SQLMap, Nikto, Hydra, Metasploit, Hashcat, John, Gobuster, FFuf, Nuclei, Burp Suite, ZAP, Responder, CrackMapExec, Evil-WinRM, Impacket, WireShark, SecLists, PEASS-ng, and 100+ more.

## Vulnerable Lab (Optional)

```bash
# Start with lab targets for practice
docker compose --profile lab up -d
```

Lab targets (all intentionally vulnerable):
| Target | Port | Description |
|--------|------|-------------|
| DVWA | 8081 | Web vuln training |
| DVNA | 9091 | Node.js vulns |
| Juice Shop | 3080 | OWASP training |
| WebGoat | 8082 | Java vulns |
| Vuln API | 5001 | API security testing |
| Admin Panel | 8888 | PHP admin panel |
| MySQL | 3306 | Weak creds |
| PostgreSQL | 5433 | Default creds |
| MongoDB | 27017 | No auth |
| Redis | 6380 | No auth |
| Samba | 445 | Weak shares |
| SSH Jumphost | 2222 | admin/admin123 |
| Elasticsearch | 9200 | No auth |

## LLM Configuration

Set in `.env`:
```env
LLM_PROVIDER=anthropic
LLM_API_BASE=https://api.anthropic.com
LLM_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_API_KEY=your-key-here
```

## Commands

```bash
docker compose up -d              # Start core
docker compose --profile lab up -d # Start with lab
docker compose ps                  # Check status
docker compose logs -f worker      # Watch workers
docker compose down                # Stop all
docker compose down -v             # Stop + delete data
docker compose build               # Rebuild images
```

## Skills Maintenance

```bash
# Rebuild the skills catalog files
make skills-catalog

# Run catalog + documentation checks
make skills-check

# Run both steps in sequence
make skills-all
```

## Skills Structure

Each skill lives under `skills/<skill_name>/` and includes:
- `SKILL.md` for human-readable workflow guidance.
- `skill.yaml` for routing metadata and outputs.
- `tools.yaml` for tool definitions and install/verify commands.
- `references/` for deep-dive guides.
- `scripts/` for parsers and evidence consolidation helpers.

## Self-Improvement Loop (Daily)

TazoSploit can run a daily lab benchmark, gate learning on results, and distill short-term memory into long-term memory.

**How it works**
- **Benchmark** creates a lab job via control-plane API and scores it.
- **Gate** writes `memory/BENCHMARKS/learning_gate.json` (promote = true/false).
- **Reflection** promotes repeated/high-value facts from `memory/DAILY/` into long-term memory.

**Run once**
```bash
python3 scripts/learning/run_learning_cycle.py
```

**Environment**
```env
CONTROL_PLANE_URL=http://localhost:8000
BENCHMARK_TARGETS=dvwa
BENCHMARK_PHASE=FULL
BENCHMARK_EXPLOIT_MODE=autonomous
BENCHMARK_TIMEOUT=10800
BENCHMARK_MAX_ITERATIONS=120
BENCHMARK_SCORE_DELTA=0.0
MEMORY_PROMOTION_MODE=reflect
```

**Notes**
- For shared memory between host and Kali, bind-mount `./memory` to `/pentest/memory` (see `docker-compose.learn.yml` below).
- Reflection reports are written to `memory/REFLECTIONS/`.

Bind-mount memory:
```bash
docker compose -f docker-compose.yml -f docker-compose.learn.yml up -d
```

## Architecture

```
Frontend → API → PostgreSQL / Redis / MinIO
                    ↓
              Scheduler → Workers → Kali Containers
                                    (150+ tools + AI agent)
                                         ↓
                                   Lab Targets (optional)
```

## API Usage

```bash
# Login
TOKEN=$(curl -s http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@tazosploit.local","password":"admin123"}' \
  | jq -r '.access_token')

# Create a pentest job
curl -s http://localhost:8000/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DVWA Full Scan",
    "scope_id": "c0000000-0000-0000-0000-000000000001",
    "phase": "RECON",
    "targets": ["lab-dvwa"],
    "timeout_seconds": 3600
  }'

# Check job status
curl -s http://localhost:8000/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Repository Map

- Control plane API and services: `control-plane/main.py`, `control-plane/api/routers`, `control-plane/services`
- Execution plane worker + scheduler: `execution-plane/main.py`, `execution-plane/scheduler/main.py`, `execution-plane/scheduler/cron_worker.py`
- Kali executor + dynamic agent: `kali-executor/open-interpreter/dynamic_agent.py`, `kali-executor/open-interpreter/llm_providers.py`, `kali-executor/open-interpreter/cve_lookup.py`
- Skills system: `skills/skill_loader.py`, `skills/skills_manager.py`, `skills/SKILL_CATALOG.md`
- AI orchestration and automation: `orchestrator.py`, `multi_agent.py`, `ai_decision_engine.py`, `heartbeat.py`, `mcp_integration.py`, `nli.py`
- Frontend (Next.js): `frontend/src/app`, `frontend/src/components`
- Observability: `observability`, `config/prometheus`, `config/grafana`
- Vulnerable lab targets: `vulnerable-lab`, `docker-compose.yml` (lab profile)
- Tests: `tests/unit`, `tests/integration`, `tests/e2e`, `tests/security`

## Project Status (2026-02-05)

Full deep-dive status, gaps, and check results: `docs/PROJECT_STATUS.md`

Highlights:
- `docker-compose-all.yml` added for one-click startup
- Scheduler now frees concurrency slots from job status updates
- Cron worker now dispatches scheduled jobs to execution plane
