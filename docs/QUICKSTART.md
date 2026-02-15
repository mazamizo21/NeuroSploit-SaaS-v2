# TazoSploit — Quick Start Guide

Get the platform running in under 5 minutes.

---

## Prerequisites

- **Docker** ≥ 24.0 with Docker Compose v2
- **8 GB RAM** minimum (16 GB recommended — Kali containers use up to 4 GB each)
- An LLM provider API key (Claude, OpenAI, GLM, or a local model via LM Studio/Ollama)

---

## 1. Clone & Configure

```bash
git clone https://github.com/your-org/tazosploit.git
cd tazosploit
```

Edit `.env` with your LLM provider:

```bash
# Option A: Claude (recommended)
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_API_KEY=your-api-key-here

# Option B: GLM / Z.AI
LLM_PROVIDER=zai
LLM_MODEL=glm-4.7
ZHIPU_API_KEY=your-api-key-here

# Option C: Local model (LM Studio / Ollama)
LLM_PROVIDER=lmstudio
LLM_MODEL=qwen/qwen3-coder-next
LLM_API_BASE=http://host.docker.internal:1234/v1

# Security: Generate a random proxy token
LLM_PROXY_TOKEN=$(openssl rand -hex 32)
```

## 2. Start the Platform

```bash
# Core platform (11 containers)
docker compose up -d

# Optional: Vulnerable lab targets for testing
docker network create tazosploit-lab 2>/dev/null || true
docker compose -f docker-compose.lab.yml up -d
```

Wait ~2 minutes for all services to start. Check health:

```bash
docker compose ps
# All services should show "healthy" or "running"
```

## 3. Access the Dashboard

| Service | URL |
|---------|-----|
| **Frontend** | [http://localhost:3000](http://localhost:3000) |
| **API Docs** | [http://localhost:8000/api/docs](http://localhost:8000/api/docs) |
| **MinIO Console** | [http://localhost:9001](http://localhost:9001) |

**Default login:** `admin@tazosploit.local` / `admin123`

## 4. Run Your First Pentest

1. Log in at `http://localhost:3000`
2. Navigate to **Scopes** → Create a scope with your target IP/domain
3. Navigate to **Pentests** → **New Pentest**
4. Configure:
   - **Name:** My First Pentest
   - **Phase:** `FULL` (runs the entire kill chain)
   - **Target:** Your target IP (e.g., `172.20.0.10` for lab targets)
   - **Exploit Mode:** `autonomous` (for lab) or `explicit_only` (for production)
   - **Max Iterations:** `30` (default)
5. Click **Start**
6. Watch the **Live Intelligence** panel update in real-time

## 5. What to Expect

The agent will autonomously:

1. **Scan** — nmap port scan, service fingerprinting, tech detection
2. **Enumerate** — Web directory brute-force, subdomain discovery
3. **Exploit** — SQLi, XSS, command injection, credential attacks
4. **Post-Exploit** — Privilege escalation, credential dumping, lateral movement
5. **Report** — Generate comprehensive findings with evidence

Typical run time: 10-30 minutes depending on target complexity and iteration count.

---

## Architecture Overview

```
Frontend (Next.js :3000)
    │
    ▼
API (FastAPI :8000) ←→ PostgreSQL + Redis + MinIO
    │
    ▼
Scheduler → Worker → Kali Container (AI Agent + 150 tools)
    │                        │
    ▼                        ▼
Supervisor              Lab Targets
(monitors & corrects)   (DVWA, Juice Shop, etc.)
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full deep-dive.

---

## Common Operations

### Stop the platform
```bash
docker compose down
```

### Stop and remove all data
```bash
docker compose down -v
```

### View agent logs
```bash
# Stream live output from a worker
docker compose logs -f worker

# View Kali container logs
docker logs tazosploit-kali-1
```

### Add a new skill
```bash
mkdir skills/my_skill
# Create SKILL.md (methodology) and skill.yaml (metadata)
# Skills are mounted read-only — restart Kali to pick up changes
docker compose restart kali
```

### Switch LLM provider
Edit `.env`, change `LLM_PROVIDER` and `LLM_MODEL`, then:
```bash
docker compose restart api worker kali
```

---

## Security Hardening

For production or untrusted environments:

```bash
# Use the hardened overlay (if available)
docker compose -f docker-compose.yml -f docker-compose.secure.yml up -d
```

Key hardening measures:
- `LLM_PROXY_TOKEN` keeps API keys out of Kali containers
- Containers run with `no-new-privileges` and `NET_RAW` only
- Redis and Postgres are internal-only (no exposed ports)
- All finding output is redacted for secrets before storage

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| "No Kali containers available" | `docker compose up -d kali` |
| LLM proxy 503 | Set `LLM_PROXY_TOKEN` in `.env` |
| Empty live-intel | Job needs to run for 30s+ before first finding push |
| Agent stuck in scan loop | Supervisor will auto-detect and hint; or set `EXPLOIT_MODE=autonomous` |
| Rate limited by LLM | Increase `LLM_PROXY_RETRY_MAX` and `LLM_PROXY_RETRY_BASE_SECONDS` |

---

*For full architecture documentation, see [ARCHITECTURE.md](./ARCHITECTURE.md).*
