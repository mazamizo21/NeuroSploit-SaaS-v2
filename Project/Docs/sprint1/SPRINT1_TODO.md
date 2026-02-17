# Sprint 1 — Core Agent Loop Fixes (Tracking)

Status legend: `[ ]` todo, `[x]` done, `[~]` in progress.

## §3A — Phase State Machine (hard gates)
- [x] Create `kali-executor/open-interpreter/phase_machine.py` (Phase enum + PhaseState, transition rules, budgets).
- [x] Integrate phase machine into `dynamic_agent.py`:
  - [x] Initialize runtime phase from `JOB_PHASE` / `EFFECTIVE_PHASE` (not just `PHASE_GATE_START`).
  - [x] Emit `phase_update` events on every phase transition.
  - [x] Ensure stop/resume checkpoint restores phase state.

## §3D — Tool Phase Restrictions
- [x] Create `kali-executor/open-interpreter/tool_phase_map.py`:
  - [x] Build default tool->allowed-phases map from skills metadata.
  - [x] Provide `is_tool_allowed()` + `get_blocked_reason()`.
- [x] Integrate tool gating into command execution path in `dynamic_agent.py` (block mapped tools outside phase).

## §3B — Structured ReAct Output
- [x] Create `kali-executor/open-interpreter/structured_output.py` (dependency-light dataclass model + parse + legacy fallback).
- [x] Update `dynamic_agent.py` to optionally use structured output mode behind a feature flag (`USE_STRUCTURED_OUTPUT`).

## §4A — Tool Usage Tracker + Comfort Zone Breaker
- [x] Create `kali-executor/open-interpreter/tool_usage_tracker.py`.
- [x] Integrate into `dynamic_agent.py` (record tools; inject diversity prompt when stuck).

## §4B — Proactive Command Injection
- [x] Create `kali-executor/open-interpreter/exploitation_injector.py`.
- [x] Integrate into `dynamic_agent.py` (inject next-best exploit commands when agent stalls).

## Validation (archive logs under `Project/Docs/sprint1/validation/`)
- [x] `python -m compileall` updated Python modules.
- [x] Control-plane smoke tests (if applicable).
  - Import smoke test (venv): `Project/Docs/sprint1/validation/control_plane_import_smoke_test_sprint1_venv.txt`.
  - Unit tests (venv): `Project/Docs/sprint1/validation/pytest_unit_sprint1_venv.txt`.
  - Note: host python lacks deps (FastAPI/pytest): `Project/Docs/sprint1/validation/control_plane_import_smoke_test_sprint1.txt`.
- [x] Frontend build (if UI touched).
