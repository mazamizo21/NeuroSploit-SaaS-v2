# Project Status (Code Map + Work Needed)

**Last Reviewed:** 2026-02-05

## Code Map

- Control plane API and services: `control-plane/main.py`, `control-plane/api/routers`, `control-plane/services`
- Execution plane worker + scheduler: `execution-plane/main.py`, `execution-plane/scheduler/main.py`, `execution-plane/scheduler/cron_worker.py`, `execution-plane/worker/main.py`
- Kali executor + dynamic agent: `kali-executor/open-interpreter/dynamic_agent.py`, `kali-executor/open-interpreter/llm_providers.py`, `kali-executor/open-interpreter/cve_lookup.py`
- Skills system: `skills/skill_loader.py`, `skills/skills_manager.py`, `skills/SKILL_CATALOG.md`, `skills/SKILL_CATALOG.json`, `skills/<skill>/SKILL.md`, `skills/<skill>/tools.yaml`
- Scheduler library (APScheduler + parser): `schedulers/cron_scheduler.py`, `schedulers/job_parser.py`, `schedulers/job_types.py`
- AI orchestration and automation: `orchestrator.py`, `multi_agent.py`, `ai_decision_engine.py`, `heartbeat.py`, `mcp_integration.py`, `nli.py`
- Frontend (Next.js): `frontend/src/app`, `frontend/src/components`
- Observability: `observability`, `config/prometheus`, `config/grafana`
- Vulnerable lab targets: `vulnerable-lab`, `docker-compose.yml` (lab profile)
- Tests: `tests/unit`, `tests/integration`, `tests/e2e`, `tests/security`, plus `tests/test_new_features.py`

## What’s Implemented

- Control plane FastAPI app with routers for tenants, scopes, jobs, policies, audit, reports, attack graphs, websocket streaming, and settings. See `control-plane/main.py` and `control-plane/api/routers`.
- Execution plane worker that executes jobs in Kali containers, streams output to Redis, posts findings/loot to the API, and uploads evidence to MinIO. See `execution-plane/main.py`.
- Execution plane scheduler that dispatches tenant queues into a worker queue. See `execution-plane/scheduler/main.py`.
- Dynamic agent features (per code + docs) including session persistence, multi-model LLM support, CVE lookup, and tool fallback behaviors. See `kali-executor/open-interpreter/dynamic_agent.py`, `kali-executor/open-interpreter/llm_providers.py`, `kali-executor/open-interpreter/cve_lookup.py`.
- Skills system with a large catalog of tool and technique definitions, plus a loader and marketplace manager. See `skills/skill_loader.py`, `skills/skills_manager.py`, `skills/SKILL_CATALOG.md`.
- Multi-agent orchestration, memory store, natural language interface, MCP tool integration, and heartbeat monitoring. See `orchestrator.py`, `multi_agent.py`, `memory/memory_store.py`, `nli.py`, `mcp_integration.py`, `heartbeat.py`.
- Frontend Next.js app with pages for dashboard, agents, pentests, loot, reports, settings, and terminal. See `frontend/src/app`.
- Attack path visualization services and APIs. See `control-plane/services/attack_graph_service.py`, `control-plane/api/routers/attack_graphs.py`.

## Recently Fixed (2026-02-05)

- Added `docker-compose-all.yml` for one-click “all services + lab” startup.
- Cron worker now dispatches scheduled jobs to the execution plane queue.
- Scheduler now listens for job status updates and frees concurrency slots.
- API now accepts `FULL` and `LATERAL` phases.
- Metrics endpoint now reports job/tenant counts.
- WebSocket connections now validate tokens and tenant/job ownership.
- Job log retrieval now reads transaction logs from JSONL files.
- Added `docs/SCHEDULER.md` to cover the scheduler system.
- Fixed frontend lint warnings (unused variables, missing deps).
- Fixed shell syntax error in `vulnerable-lab/show_session_code.sh`.
- Fixed invalid escape sequences in `scripts/ultravnc_mouse_config.py`.

## What Still Needs Work

- No remaining critical gaps identified in this pass. Consider running full integration tests and Docker lab validation.

## Checks Performed

- Python syntax: `python3 -m py_compile` on repo sources (no errors).
- Shell syntax: `bash -n` on `*.sh` (no errors).
- Frontend lint: `npm run lint` in `frontend` (clean).
- Not run: unit/integration/e2e tests, docker integration tests, end-to-end lab runs.
