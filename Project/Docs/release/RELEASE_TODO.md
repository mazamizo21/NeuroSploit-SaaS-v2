# Release Engineering TODO

This file tracks post-sprint release hardening work.

## Implemented

- [x] RC validation runner script: `scripts/validate_release_candidate.sh`
- [x] CI pipeline: `.github/workflows/release-validation.yml`
- [x] Dev compose override: `docker-compose.dev.yml` (uvicorn --reload)

## Pending (optional improvements)

- [ ] Add `make rc` / `make dev` shortcuts.
- [ ] Add a `docker compose down` cleanup mode to RC script (default: leave services up).
- [ ] Add a `pytest.ini` to formalize unit vs integration tests.
