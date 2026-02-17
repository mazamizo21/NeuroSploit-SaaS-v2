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

- [~] **T2 — Fix tenant scoping + live push correctness (worker)**
  - Root cause: `JobResponse` does **not** include `tenant_id`, but worker used `job_details.get('tenant_id')`.
  - Effects: `TENANT_ID` env passed to agent is empty → memory/graph cross-tenant contamination risk; live findings/loot push tenant_id empty.
  - Fix: pass tenant_id from queue payload into `_run_in_container` + live push calls.
  - Validate by resuming a job and confirming:
    - agent env has correct `TENANT_ID`
    - memory files under `/pentest/memory/` are tenant-prefixed (not `_*.json`)
    - live pushes succeed (worker logs)

- [ ] **T3 — Add regression coverage for exploit gate on dual-use fuzzers**
  - Ensure `scan-with-unexploited-findings` gate blocks only enum-intent ffuf/wfuzz and allows exploit-intent.

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
