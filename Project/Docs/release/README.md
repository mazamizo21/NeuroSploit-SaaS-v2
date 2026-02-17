# Release / CI Validation

This folder contains release-candidate (RC) validation artifacts and operational guidance.

## Local: run RC validation

```bash
bash scripts/validate_release_candidate.sh
```

Artifacts are written to:

- `Project/Docs/release/validation/<timestamp>/`

## CI

GitHub Actions runs the same validation script:

- Workflow: `.github/workflows/release-validation.yml`
- Artifact: `release-validation-<RC_TS>`

## Dev workflow: hot-reload API

To avoid having to restart the `api` container after changing control-plane code, use the dev override:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d api
```

This runs uvicorn with `--reload` **and** keeps `--no-access-log` enabled (to avoid leaking JWTs via query params).
