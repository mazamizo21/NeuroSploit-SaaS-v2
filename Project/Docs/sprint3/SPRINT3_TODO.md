# Sprint 3 — Job Settings (Redis) (Tracking)

Status legend: `[ ]` todo, `[x]` done, `[~]` in progress.

## §3A — Job Settings (Control Plane)
- [x] Add per-job settings endpoints (store JSON in Redis):
  - [x] `GET /api/jobs/{id}/settings`
  - [x] `PUT /api/jobs/{id}/settings`

## §3B — Job Settings (Execution Plane / Agent)
- [x] Create `kali-executor/open-interpreter/project_settings.py` (defaults + Redis overrides + env application).
- [x] Load/apply job settings early in `kali-executor/open-interpreter/dynamic_agent.py` (fail-open; allowlist).

## Validation (archive logs under `Project/Docs/sprint3/validation/`)
- [x] `python -m compileall` updated/new modules: `Project/Docs/sprint3/validation/python_compileall_sprint3_job_settings.txt`.
- [x] Unit tests (host venv): `Project/Docs/sprint3/validation/pytest_unit_sprint3_venv_tests_unit.txt`.
- [x] Full pytest (host venv): `Project/Docs/sprint3/validation/pytest_root_sprint3_venv_fixed.txt`.
- [x] Docker smoke test (Kali can reach Redis + apply per-job settings):
  - Runner: `scripts/validate_sprint3_job_settings_docker.sh`
  - Output: `Project/Docs/sprint3/validation/docker_job_settings_smoke_test_sprint3.txt`
