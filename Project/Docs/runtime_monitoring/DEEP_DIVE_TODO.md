# Deep Dive TODO (Runtime + Code) — 2026-02-17

Scope: job `c638254e-e0b0-4c76-bc7b-6a6c91fc7281` + platform reliability/security fixes discovered during monitoring.

## Active TODOs

- [ ] **T1 — Telemetry deep dive (job artifacts)**
  - Parse + summarize:
    - `dynamic_agent.log` (BLOCKED/REJECTED/ERROR patterns)
    - `agent_executions.jsonl` (tool_used quality, repeats, exit codes)
    - `llm_interactions.jsonl` (decision quality, token/cost drift)
    - `structured_findings.json` + `vuln_tracker.json` (consistency + proof)
    - `arsenal.json` (tokens/creds present and referenced correctly)

- [x] **T2 — Fix tenant scoping + live push correctness (worker)**
  - Root cause: `JobResponse` does **not** include `tenant_id`, but worker used `job_details.get('tenant_id')`.
  - Effects: `TENANT_ID` env passed to agent is empty → memory/graph cross-tenant contamination risk; live findings/loot push tenant_id empty.
  - Fix: pass tenant_id from queue payload into `_run_in_container` + live push calls.
  - Validate by resuming a job and confirming:
    - agent env has correct `TENANT_ID`
    - memory files under `/pentest/memory/` are tenant-prefixed (not `_*.json`)
    - live pushes succeed (worker logs)

- [x] **T3 — Add regression coverage for exploit gate on dual-use fuzzers**
  - Ensure `scan-with-unexploited-findings` gate blocks only enum-intent ffuf/wfuzz and allows exploit-intent.

- [x] **T6 — Supervisor override TTL hardening (control-plane)**
  - Fix: per-job keys `job:{id}:supervisor_enabled` + `job:{id}:supervisor_provider` now use TTL aligned to job timeout (was fixed 24h).
  - Fix: resume endpoint re-asserts per-job supervisor keys so resumed jobs don't lose supervisor behavior if keys expired.

- [x] **T7 — max_iterations=0 unlimited semantics (dynamic_agent)**
  - Fix: treat `max_iterations<=0` as unlimited in the main run loop (and near-end checks).
  - Add regression test: `tests/unit/test_dynamic_agent_unlimited_iterations.py`.

- [x] **T8 — Docker smoke test extended for new per-job settings keys**
  - `scripts/validate_sprint3_job_settings_docker.sh` now asserts:
    - AUTO_COMPLETE_IDLE_ITERATIONS
    - AUTO_COMPLETE_MIN_ITERATIONS
    - LLM_THINKING_ENABLED

- [x] **T9 — Agent-side per-job settings allowlist hardening**
  - Fix: `kali-executor/open-interpreter/project_settings.py` no longer allowlists every DEFAULT_AGENT_SETTINGS key.
  - Align allowlist with control-plane `api.utils.job_settings` so direct Redis writes cannot override secrets or sensitive knobs.

- [ ] **T4 — Enable supervisor + persistence for full phase progression**
  - Set `job:{id}:supervisor_enabled=true` (Redis) and `allow_persistence/allow_defense_evasion=true` (DB).
  - Resume the job and monitor until it reaches post-exploit objectives (persist/lateral/privesc/exfil evidence).

- [ ] **T5 — Cost control / runaway iteration guard**
  - Problem: `max_iterations>=2000` disables auto-complete by default → can burn tokens after proofs.
  - Decide fix:
    - lower max_iterations for lab jobs, OR
    - set auto-complete thresholds via job config/settings.

## Validation Artifacts

- Store all command outputs and snapshots under `Project/Docs/runtime_monitoring/<timestamp>_*`.
- Store code validation (compileall/unittest) under `Project/Docs/*/validation/<timestamp>_*`.
