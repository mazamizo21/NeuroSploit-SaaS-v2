# TazoSploit Owner LLM Settings (OpenClaw-style)

## Overview
This document describes the owner-only, OpenClaw-style LLM configuration layer added to TazoSploit. It mirrors OpenClaw’s provider patterns (Option A API keys and Option B tokens) and its thinking-level controls, while preserving the existing GLM/Z.AI path as the safe fallback.

Core goals:
- Allow the SaaS owner to configure all supported LLM providers in one place.
- Support both API keys and token-based auth (e.g., Claude setup-token, OpenAI/Codex tokens).
- Add a global thinking-level setting with safe mapping for Z.AI (binary thinking).
- Keep current GLM behavior stable when owner config is missing or incomplete.

## High-Level Architecture
- Owner config lives in the tenant settings under `settings.llm_settings`.
- The internal LLM proxy now resolves the owner config first and falls back to env-based config.
- The executor continues to call the internal proxy via `LLM_PROXY_URL`, so no secret keys live in the Kali container.
- The Settings UI displays an Owner LLM Settings panel only if the current user is the owner.

## Owner-Only Access Model
Owner access requires:
- User role: `admin`.
- Tenant ID matches `SAAS_OWNER_TENANT_ID`.
- Optional email match if `SAAS_OWNER_EMAIL` is set.

If the user is not the owner, the LLM config endpoints return `403`, and the UI silently hides the owner settings section.

Env vars:
- `SAAS_OWNER_TENANT_ID` (default: `a0000000-0000-0000-0000-000000000001`)
- `SAAS_OWNER_EMAIL` (optional)

## Data Model
Owner LLM settings are stored at:
- `Tenant.settings.llm_settings`

Structure:
- `default_provider`: string
- `thinking_level`: string
- `providers`: object keyed by provider id

Provider entry fields:
- `credential_encrypted`: encrypted secret
- `enabled`: boolean (provider toggle)
- `auth_method`: `api_key`, `setup_token`, `oauth_token`, `bearer_token`
- `api_style`: `openai` or `anthropic`
- `api_base`: provider base URL
- `model`: provider default model
- `updated_at`: ISO timestamp

Secrets are obfuscated at rest using `SECRET_KEY` via a lightweight XOR scheme and masked in UI. This is not a replacement for KMS/Vault.

## Internal LLM Proxy Flow
The internal proxy (`/api/internal/llm/chat`) resolves LLM config in this order:
1. Owner config from `settings.llm_settings`.
2. Env-based config (current behavior).

If owner config is present but missing credentials, the proxy returns a `500` with an owner config error.

The proxy supports two API styles:
- `openai` style: `/chat/completions` with `Authorization: Bearer <token>`
- `anthropic` style: `/messages` with either:
  - `x-api-key: <token>` for API key auth
  - `Authorization: Bearer <token>` for setup tokens and bearer tokens

### Thinking Levels
The proxy injects a system directive based on `thinking_level`:
- `off` disables any directive injection.
- `minimal`, `low`, `medium`, `high`, `xhigh` add increasing reasoning instructions.
- Z.AI / GLM providers only support on/off; any level above `off` maps to `low`.

Env override:
- `LLM_THINKING_LEVEL=off` can provide a default when owner settings are not set.

## UI: Owner LLM Settings Panel
Location:
- `frontend/src/app/settings/page.tsx`

Behavior:
- Loads `/api/v1/settings/llm/config`.
- If successful, shows a panel to manage provider credentials and defaults.
- If 403 or error, panel is hidden.

The UI allows:
- Setting the global default provider.
- Setting the global thinking level.
- Managing credentials per provider, including Option A/Option B auth method selection.
- Enabling/disabling providers (only enabled providers can be selected as default or for jobs).

## Provider Catalog (Owner UI)
Configured provider options in UI:
- `openai`
- `openai-codex`
- `anthropic`
- `openrouter`
- `vercel-ai-gateway`
- `moonshot`
- `kimi-coding`
- `synthetic`
- `opencode`
- `zai`
- `glm`
- `minimax`
- `venice`
- `google`
- `google-vertex`
- `google-antigravity`
- `google-gemini-cli`
- `qwen-portal`
- `xai`
- `groq`
- `cerebras`
- `mistral`
- `github-copilot`
- `ollama`
- `xiaomi`
- `amazon-bedrock`

For providers without known bases/models, the UI keeps fields editable.
Model IDs (as in OpenClaw docs) are prefilled in the UI in `frontend/src/lib/llmProviders.ts`.
Google `google-vertex`, `google-antigravity`, and `google-gemini-cli` entries default to OAuth token auth, matching OpenClaw’s guidance.

## Model Selection (GUI)
Owner LLM Settings now provides:
- A model dropdown populated from the OpenClaw model lists for each provider.
- A `Custom...` option that reveals a text input for any additional model.

All model strings use the OpenClaw format (`provider/model`). The internal proxy strips the provider prefix before calling upstream APIs, so you can keep the OpenClaw-style IDs in the UI.

## API Endpoints
Owner-only endpoints:
- `GET /api/v1/settings/llm/config`
- `POST /api/v1/settings/llm/config`
- `POST /api/v1/settings/llm/providers/{provider_id}`
User endpoints:
- `GET /api/v1/settings/llm/options` (enabled providers + global default)

Payloads:
- Defaults update:
  - `default_provider` (string or null)
  - `thinking_level` (string)
- Provider update:
  - `auth_method`, `api_style`, `api_base`, `model`, `credential`, `enabled`
  - `clear: true` to remove credentials

Legacy endpoints for per-tenant Anthropic key and Claude setup-token still exist, but the Settings UI no longer exposes them to avoid duplication. Use the Owner LLM Settings panel for all credentials going forward.

## GLM Safety
GLM remains safe because:
- Env-based fallback keeps `LLM_PROVIDER=glm` working.
- Owner config is optional; if no owner LLM is configured, it won’t override env behavior.
- Z.AI thinking defaults map to low for compatibility.

## Job-Level Provider Override
- Jobs can optionally set `llm_provider` to override the global default.
- Per-job selection always supersedes the global default.
- The UI exposes this in the Create Pentest form as “LLM Provider Override”.
- The executor passes this to the internal proxy as `provider_override`.
- Internally this is conveyed via `LLM_PROVIDER_OVERRIDE` in the Kali container environment.
- If the provider is not enabled, job creation fails with a 400.

## Environment Variables
Key env vars:
- `SAAS_OWNER_TENANT_ID`
- `SAAS_OWNER_EMAIL`
- `LLM_PROXY_TOKEN`
- `LLM_PROXY_URL`
- `LLM_PROXY_TIMEOUT_SECONDS`
- `LLM_PROXY_RETRY_MAX`
- `LLM_PROXY_RETRY_BASE_SECONDS`
- `LLM_THINKING_LEVEL`

Existing env vars still supported:
- `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_BASE`
- `ZHIPU_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`

## Setup Guide (Owner)
1. Ensure `SAAS_OWNER_TENANT_ID` and optionally `SAAS_OWNER_EMAIL` are set.
2. Log in as an admin user for the owner tenant.
3. Navigate to Settings and open Owner LLM Settings.
4. Configure provider credentials (GUI-only):
Select the provider card.
Choose the **Auth Method**: Option A (`api_key`) for standard API keys, Option B (`setup_token` or `oauth_token`) for subscription or OAuth tokens.
Paste the token/key into **Credential** and click **Save**.
5. Select a **Model** from the dropdown (or choose **Custom...** and paste a model id).
6. Enable the providers you want available for jobs.
7. Choose the global default provider and thinking level.
8. Confirm the Kali executor uses the internal proxy via `LLM_PROXY_URL` and `LLM_PROXY_TOKEN`.

Token examples:
- Claude Pro/Max setup token: choose `setup_token` under the Anthropic provider and paste the output of `claude setup-token`.
- OpenAI Codex OAuth token: choose `oauth_token` under OpenAI Codex and paste the token.
- Google Antigravity / Vertex / Gemini CLI: choose `oauth_token` for those providers and paste the OAuth token.

## Example cURL
Set defaults:
```
curl -X POST http://localhost:8000/api/v1/settings/llm/config \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"default_provider":"anthropic","thinking_level":"medium"}'
```

Set Anthropic setup-token:
```
curl -X POST http://localhost:8000/api/v1/settings/llm/providers/anthropic \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"auth_method":"setup_token","api_style":"anthropic","credential":"<setup-token>","model":"anthropic/claude-sonnet-4-5","enabled":true}'
```

Set GLM/Z.AI:
```
curl -X POST http://localhost:8000/api/v1/settings/llm/providers/glm \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"auth_method":"api_key","api_style":"openai","api_base":"https://api.z.ai/api/coding/paas/v4","credential":"<z.ai key>","model":"glm-4.7","enabled":true}'
```

Set job-level override:
```
curl -X POST http://localhost:8000/api/v1/jobs \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Override Provider Test",
    "phase": "RECON",
    "targets": ["dvwa"],
    "scope_id": "c0000000-0000-0000-0000-000000000001",
    "llm_provider": "anthropic"
  }'
```

## Security Notes
- Secrets are obfuscated using `SECRET_KEY`. This is not a cryptographic KMS.
- For production, replace with Vault/KMS-backed encryption and rotate keys regularly.
- The internal LLM proxy should stay on trusted networks and always require `LLM_PROXY_TOKEN`.

## Files Changed (for this feature)
- `control-plane/api/utils/crypto.py`
- `control-plane/api/routers/settings.py`
- `control-plane/api/routers/internal_llm.py`
- `frontend/src/app/settings/page.tsx`
- `frontend/src/lib/llmProviders.ts`
- `frontend/src/app/pentests/page.tsx`
- `control-plane/api/models.py`
- `control-plane/api/routers/jobs.py`
- `control-plane/db/init.sql`
- `execution-plane/worker/main.py`
- `kali-executor/open-interpreter/llm_client.py`
- `.env.example`

## Quick Troubleshooting
- 403 when loading owner settings:
  - Check `SAAS_OWNER_TENANT_ID`, `SAAS_OWNER_EMAIL`, and user role.
- 500 from LLM proxy with owner provider error:
  - Ensure the owner provider has a credential saved.
- GLM not working after owner config:
  - Set default provider to `glm` in owner settings or remove owner config to allow env fallback.
- Claude setup-token not working:
  - Use `auth_method=setup_token` and ensure API style is `anthropic`.
