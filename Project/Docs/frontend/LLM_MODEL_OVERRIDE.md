# Per-Job LLM Model Override (Redamon-Style Optgroups)

## Goal
Add a Redamon-style grouped LLM model dropdown (optgroups + friendly labels) to the **Create New Pentest** form, and wire it end-to-end so each job can override the model used by the internal LLM proxy.

## UX
- **LLM Provider Override** (existing): chooses a provider id (must be enabled by owner settings).
- **LLM Model Override** (new): appears once a provider override is selected.
  - Uses `modelGroups` + `modelLabels` from `frontend/src/lib/llmProviders.ts` to render `<optgroup>`.
  - Supports `Custom...` for arbitrary model ids.

Key file:
- `frontend/src/app/pentests/page.tsx`

## Data Model / API
- `jobs.llm_model` (nullable) stores the per-job model override.
- `POST /api/v1/jobs` accepts `llm_model`.
- `GET /api/v1/jobs/{id}` returns `llm_model`.

Key files:
- `control-plane/api/models.py`
- `control-plane/api/routers/jobs.py`

## Executor → Proxy wiring
The Kali executor always calls the **internal LLM proxy** when `LLM_PROXY_URL` is set. To support per-job model overrides, we pass a dedicated env var and forward it to the proxy:

- Worker sets (per exec):
  - `LLM_MODEL_OVERRIDE=<provider/model>` (only when job has override)
  - `LLM_MODEL=<provider/model>` (for local heuristics/logging)

- Kali `llm_client.py` forwards to proxy JSON payload:
  - `model_override=<LLM_MODEL_OVERRIDE>`

- Control-plane proxy (`/api/internal/llm/chat`) accepts `model_override` and uses it as the upstream model (after prefix normalization).

Key files:
- `execution-plane/worker/main.py`
- `kali-executor/open-interpreter/llm_client.py`
- `control-plane/api/routers/internal_llm.py`

## DB migration strategy (hands-off)
- `control-plane/db/init.sql` includes the `llm_model` column and an idempotent `ALTER TABLE` block.
- `control-plane/main.py` also performs a best-effort runtime schema upgrade to add `jobs.llm_model` when missing (for existing Postgres volumes).

## Security notes
- We **do not** allow per-job `api_base` overrides (avoids proxy-side SSRF).
- `llm_model` / `model_override` is validated to reject whitespace and prevent cross-provider mismatches when a prefix is present.

## Validation artifacts
- Python compileall: `Project/Docs/control-plane/validation/python_compileall_llm_model_override.txt`
- Frontend lint: `Project/Docs/frontend/validation/next_lint_llm_model_override.txt`
- Frontend build: `Project/Docs/frontend/validation/next_build_llm_model_override.txt`
