# TazoSploit Constitution

## Project Identity

**TazoSploit** is an AI-powered autonomous penetration testing platform built as a multi-tenant SaaS product. It orchestrates LLM-driven attack agents inside Kali Linux containers against authorized targets, with a supervisory AI layer that watches for stalls and guides strategy.

## Core Principles

### 1. Evidence-First Exploitation (The Proof Gate)

**Nothing is "exploited" unless concrete proof exists in stdout/stderr or a saved artifact.**

- SQLi requires actual dump markers or auth-bypass tokens from real commands
- LFI/Traversal requires `root:x:` or equivalent secret markers in output
- RCE requires `uid=` output from actual command execution
- File upload requires execution evidence beyond just upload success
- High/Critical findings are **automatically downgraded to Medium** if evidence is weak or speculative
- Proof is stored as `cmd:` + `output:` pairs with redacted secrets
- The `ENFORCE_EXPLOITATION_PROOF` flag defaults to `true`
- A vulnerability can be marked `not_exploitable` with a concrete reason after `EXPLOITATION_PROOF_MAX_ATTEMPTS_PER_VULN` (default: 5) failed attempts

### 2. Authorized Access Only

- Every pentest runs against **explicitly authorized targets** defined in Scopes
- Scope enforcement is strict: commands are blocked if they target IPs/hosts outside the allowlist
- External targets require additional `authorization_confirmed` flag
- Self-registration is disabled by default — the agent cannot create accounts without explicit policy permission
- Subnet scans, localhost scans, and Docker infrastructure scanning are blocked unless explicitly enabled

### 3. Separation of Concerns (Control/Execution/Kali)

The architecture follows a strict three-plane separation:

- **Control Plane** (FastAPI API): Manages tenants, scopes, jobs, findings, auth, and serves as the LLM proxy
- **Execution Plane** (Scheduler + Workers + Supervisor): Orchestrates job dispatch, container lifecycle, and quality oversight
- **Kali Plane** (Kali containers + Dynamic Agent): Executes actual pentest commands with 150+ tools + LLM reasoning

No plane should reach into another's internal state. Communication flows through:
- Redis pub/sub for real-time events
- Redis queues for job dispatch
- HTTP API for structured data
- Docker exec for container interaction (worker → kali only)

### 4. Supervisor Independence

The Supervisor service is architecturally separate from the attack agent:

- It subscribes to Redis `job:*:output` and `job:*:status` channels
- It maintains its own heuristic state per job (stall detection, noop loops, scan loops, repeat commands)
- It can use a **different LLM provider** than the attack agent to avoid shared blind spots
- When it detects problems, it writes hint files into the Kali container via Docker exec
- The agent reads hints from `supervisor_hints.jsonl` and acts on them
- Supervisor LLM calls fall back to **stub decisions** on 429/5xx errors rather than failing audits

### 5. Defense-in-Depth Redaction

- API keys and tokens are redacted before they hit Redis or the UI
- Patterns: `sk-***`, `Bearer ***`, Zhipu key patterns
- Curl progress-meter noise is stripped from evidence
- JWTs and passwords in proof snippets are redacted
- The `docker-compose.secure.yml` overlay removes API keys from Kali containers entirely

## Code Quality Standards

### Python (Backend)

- **Structured logging**: Use `structlog` with JSON output, timestamped, with context vars
- **Async-first**: All service main loops use `asyncio`. Workers use sync subprocess for shell commands
- **Error handling**: Never let streaming/logging errors kill a job. Wrap Redis/Docker calls in try/except
- **Type hints**: Use dataclasses for structured state. Type annotations on public methods
- **Environment-driven config**: All tuning knobs via environment variables with sensible defaults
- **No hardcoded exploits**: The Dynamic Agent has NO hardcoded solution paths — all behavior comes from the system prompt and LLM reasoning

### TypeScript/React (Frontend)

- **Next.js App Router** with client components (`'use client'`)
- **SWR** for data fetching with automatic revalidation
- **Tailwind CSS** for styling, dark theme by default
- **Component patterns**: Sidebar navigation, Card containers, LiveLogViewer with xterm.js, MITRE heatmap
- **Redux Toolkit** for complex state (dopamine feed, etc.)

### General

- Functions should be small and single-purpose
- Private methods prefixed with `_`
- Constants at module top level, SCREAMING_SNAKE_CASE
- Config via env vars, never hardcode credentials
- Idempotent database migrations via `DO $$ BEGIN ... EXCEPTION WHEN ... END $$`

## Testing Requirements

- **Unit tests** (`tests/unit/`): Test individual functions, normalization, parsing
- **Integration tests** (`tests/integration/`): Test service interactions with mocked dependencies
- **E2E tests** (`tests/e2e/`): Full pipeline tests against running Docker stack
- **Security tests** (`tests/security/`): OWASP-style API security audit
- **Load tests** (`tests/load/`): Concurrent job stress testing
- Every PR should include evidence of test execution, not just code changes

## Docker/Container Conventions

- **Multi-stage builds** where possible
- **Health checks** on every service with appropriate intervals
- **Named networks**: `control-net`, `exec-net`, `kali-net`, `lab-net` — each with clear trust boundaries
- **Volume persistence**: `postgres-data`, `redis-data`, `minio-data`, `kali-output`, `kali-memory`
- **Security constraints on Kali**: `cap_drop: ALL`, `cap_add: NET_RAW`, `no-new-privileges`, resource limits (2 CPU, 4GB)
- **Profile-gated lab targets**: Lab services only start with `--profile lab`
- Container names follow `tazosploit-<service>` or `lab-<target>` pattern

## API Design Patterns

- **RESTful routing**: `/api/v1/<resource>` with standard CRUD
- **Internal routes**: `/api/internal/llm/chat` for LLM proxy (token-authenticated)
- **Auth**: JWT Bearer tokens for users, `internal-<SECRET_KEY>` for service-to-service
- **CORS**: Explicit origin allowlist, no wildcards
- **Rate limiting**: Redis-backed, per-path configurable
- **Request IDs**: UUID per request, returned in `X-Request-ID` header
- **Error format**: `{ "error": string, "status_code": int, "request_id": string }`
- **Findings normalization**: Worker normalizes severity, strips unknown keys, generates titles from metadata

## LLM Integration Patterns

- **LLM Proxy**: All LLM calls route through the control plane's `/api/internal/llm/chat` endpoint
- **Provider abstraction**: Support for Anthropic, Zhipu (ZAI/GLM), and custom providers via `llm_providers.py`
- **Per-job provider override**: Jobs can specify `llm_provider` to use a different model
- **Token budgets**: Configurable `LLM_MAX_COMPLETION_TOKENS` (default: 1024), output truncation via `MAX_STDOUT_CHARS`
- **Retry with backoff**: LLM proxy retries with exponential backoff on transient failures
- **Cost tracking**: Token usage and estimated cost stored per job and per LLM call
- **Conversation management**: Single system prompt + rolling conversation with truncated tool outputs

## Operational Patterns

### Job Lifecycle
1. User creates job via API → status: `pending`
2. API enqueues to Redis `tenant:<id>:job_queue` → status: `queued`
3. Scheduler pops from tenant queue, pushes to `worker:job_queue`
4. Worker picks up, finds Kali container, execs Dynamic Agent → status: `running`
5. Agent runs iterations, streams output to Redis pub/sub
6. Worker collects results, posts findings to API → status: `completed` or `failed`

### Supervisor Actions
- `ignore` — no action needed
- `hint` — write directive to `supervisor_hints.jsonl` in Kali container
- `retry` — stronger hint to change approach
- `reset` — full conversation reset with replan
- `stop` — publish `CANCEL` to job control channel

### Skills System
- Skills live in `skills/<skill_name>/` with `SKILL.md`, `skill.yaml`, `tools.yaml`
- `SkillRouter` selects relevant skills based on phase, target type, evidence, and service hints
- Skills are injected into the Dynamic Agent's system prompt, not hardcoded
- Maximum 3-8 skills per run depending on phase

## Known Constraints & Pain Points

1. **Container restart orphan bug**: When Kali containers restart, in-flight jobs lose their container mapping. Workers may not detect this.
2. **Supervisor 429 stub decisions**: When the LLM proxy is rate-limited, supervisor falls back to stub logic which may not be optimal.
3. **Finding deduplication**: The same vulnerability can be reported multiple times across iterations with slightly different titles.
4. **Scan loop detection**: The agent sometimes gets stuck in enumeration loops. The supervisor's scan_loop detection helps but has false positives.
5. **Evidence upload reliability**: Evidence files in Kali containers need to be reliably extracted before the container is recycled.
6. **Token context window**: Long-running jobs accumulate large conversation histories that may exceed model context limits.
