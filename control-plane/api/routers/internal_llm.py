"""TazoSploit SaaS v2 - Internal LLM Proxy Router

Purpose:
- Allow execution-plane containers (e.g., Kali executor) to call an internal endpoint for LLM
  completions WITHOUT embedding provider API keys in the executor container.

Security:
- Requires X-LLM-Proxy-Token header to match env LLM_PROXY_TOKEN.
- Endpoint is intended for internal Docker networks only.

Notes:
- Currently implements the Zhipu (z.ai) OpenAI-compatible chat completions path.
- Designed to be extended for other providers later.
"""

import os
import uuid
import asyncio
import random
import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Tenant
from ..utils.crypto import decrypt_value

logger = logging.getLogger(__name__)

router = APIRouter()

OWNER_TENANT_ID = os.getenv("SAAS_OWNER_TENANT_ID", "a0000000-0000-0000-0000-000000000001").strip()

DEFAULT_OPENAI_BASE = "https://api.openai.com/v1"
DEFAULT_ANTHROPIC_BASE = "https://api.anthropic.com/v1/messages"
DEFAULT_ZAI_BASE = "https://api.z.ai/api/coding/paas/v4"

DEFAULT_PROVIDER_BASES = {
    "openai": DEFAULT_OPENAI_BASE,
    "openai-codex": DEFAULT_OPENAI_BASE,
    "codex": DEFAULT_OPENAI_BASE,
    "openrouter": "https://openrouter.ai/api/v1",
    "moonshot": "https://api.moonshot.ai/v1",
    "synthetic": "https://api.synthetic.new/anthropic",
    "venice": "https://api.venice.ai/api/v1",
    "minimax": "https://api.minimax.io/anthropic",
    "qwen-portal": "https://portal.qwen.ai/v1",
    "xiaomi": "https://api.xiaomimimo.com/anthropic",
    "ollama": "http://host.docker.internal:11434/v1",
    "lmstudio": "http://host.docker.internal:1234/v1",
    "lm-studio": "http://host.docker.internal:1234/v1",
    "cerebras": "https://api.cerebras.ai/v1",
    "anthropic": DEFAULT_ANTHROPIC_BASE,
    "claude": DEFAULT_ANTHROPIC_BASE,
    "z.ai": DEFAULT_ZAI_BASE,
    "zai": DEFAULT_ZAI_BASE,
    "zhipu": DEFAULT_ZAI_BASE,
    "glm": DEFAULT_ZAI_BASE,
}

MODEL_PREFIX_ALIASES = {
    "openai": ["openai"],
    "openai-codex": ["openai-codex", "codex"],
    "codex": ["openai-codex", "codex"],
    "anthropic": ["anthropic", "claude"],
    "claude": ["anthropic", "claude"],
    "openrouter": ["openrouter"],
    "vercel-ai-gateway": ["vercel-ai-gateway"],
    "moonshot": ["moonshot"],
    "kimi-coding": ["kimi-coding"],
    "synthetic": ["synthetic"],
    "opencode": ["opencode"],
    "zai": ["zai", "z.ai", "z-ai", "zhipu", "glm"],
    "z.ai": ["zai", "z.ai", "z-ai", "zhipu", "glm"],
    "zhipu": ["zai", "z.ai", "z-ai", "zhipu", "glm"],
    "glm": ["glm", "zai", "z.ai", "z-ai", "zhipu"],
    "venice": ["venice"],
    "minimax": ["minimax"],
    "google": ["google"],
    "google-vertex": ["google-vertex"],
    "google-antigravity": ["google-antigravity"],
    "google-gemini-cli": ["google-gemini-cli"],
    "qwen-portal": ["qwen-portal", "qwen"],
    "xai": ["xai"],
    "groq": ["groq"],
    "cerebras": ["cerebras"],
    "mistral": ["mistral"],
    "github-copilot": ["github-copilot", "copilot"],
    "ollama": ["ollama"],
    "lmstudio": ["lmstudio", "lm-studio"],
    "lm-studio": ["lmstudio", "lm-studio"],
    "xiaomi": ["xiaomi"],
    "amazon-bedrock": ["amazon-bedrock", "bedrock"],
    "bedrock": ["amazon-bedrock", "bedrock"],
}

THINKING_DIRECTIVES = {
    "minimal": "Thinking level: minimal. Keep internal reasoning brief. Provide only the final answer.",
    "low": "Thinking level: low. Keep reasoning concise and focused. Provide only the final answer.",
    "medium": "Thinking level: medium. Think carefully through steps and edge cases. Provide only the final answer.",
    "high": "Thinking level: high. Use deep, careful reasoning. Provide only the final answer.",
    "xhigh": "Thinking level: xhigh. Use maximum reasoning budget. Provide only the final answer.",
}


class LLMChatRequest(BaseModel):
    messages: List[Dict[str, Any]] = Field(..., description="OpenAI-style messages array")
    max_tokens: int = Field(default=2048, ge=1, le=8192)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    provider_override: Optional[str] = Field(default=None, description="Optional provider id override")


async def _load_owner_llm_settings(db: AsyncSession) -> dict:
    if not OWNER_TENANT_ID:
        return {}
    try:
        owner_uuid = uuid.UUID(OWNER_TENANT_ID)
    except Exception:
        return {}
    tenant = await db.get(Tenant, owner_uuid)
    if not tenant or not tenant.settings:
        return {}
    return tenant.settings.get("llm_settings", {}) or {}


async def _load_owner_subscription_token(db: AsyncSession) -> Optional[str]:
    if not OWNER_TENANT_ID:
        return None
    try:
        owner_uuid = uuid.UUID(OWNER_TENANT_ID)
    except Exception:
        return None
    tenant = await db.get(Tenant, owner_uuid)
    if not tenant:
        return None

    encrypted = None
    try:
        encrypted = getattr(tenant, "subscription_token_encrypted", None)
    except Exception:
        encrypted = None

    if not encrypted and getattr(tenant, "api_key_encrypted", None):
        if tenant.api_key_encrypted.startswith("TOKEN:"):
            encrypted = tenant.api_key_encrypted[6:]

    if not encrypted:
        return None
    try:
        return decrypt_value(encrypted)
    except Exception:
        return None


def _is_setup_token(credential: str) -> bool:
    """Check if a credential looks like a Claude OAuth/setup token (sk-ant-oat*)."""
    return bool(credential and credential.startswith("sk-ant-oat"))


def _infer_api_style(provider_id: str) -> str:
    if provider_id in {"anthropic", "claude", "vercel-ai-gateway", "minimax", "synthetic", "kimi-coding", "xiaomi"}:
        return "anthropic"
    return "openai"


def _normalize_model(provider_id: str, model: str) -> str:
    if not model:
        return model
    provider_key = (provider_id or "").strip().lower()
    value = model.strip()
    prefixes = MODEL_PREFIX_ALIASES.get(provider_key, [])
    if provider_key and provider_key not in prefixes:
        prefixes = [provider_key] + prefixes
    for prefix in prefixes:
        if not prefix:
            continue
        if value.lower().startswith(prefix.lower() + "/"):
            return value[len(prefix) + 1 :]
    return value


def _is_enabled(cfg: dict) -> bool:
    if cfg is None:
        return False
    enabled = cfg.get("enabled")
    if enabled is None:
        return bool(cfg.get("credential_encrypted"))
    return bool(enabled)


def _apply_thinking(messages: List[Dict[str, Any]], thinking_level: Optional[str], provider_id: str) -> List[Dict[str, Any]]:
    if not thinking_level:
        return messages
    level = thinking_level.strip().lower()
    if level == "off":
        return messages
    if provider_id in {"z.ai", "zai", "zhipu", "glm"}:
        # Z.AI only supports on/off; map any non-off to low.
        level = "low"
    directive = THINKING_DIRECTIVES.get(level)
    if not directive:
        return messages
    updated = list(messages or [])
    if updated and updated[0].get("role") == "system":
        updated[0]["content"] = f"{updated[0].get('content', '')}\n\n{directive}"
    else:
        updated = [{"role": "system", "content": directive}] + updated
    return updated


def _resolve_env_provider_config() -> dict:
    provider = os.getenv("LLM_PROVIDER", "zhipu").lower().strip()
    model = os.getenv("LLM_MODEL", "").strip()
    api_base = os.getenv("LLM_API_BASE", "").strip()
    api_style = _infer_api_style(provider)
    auth_method = "api_key"

    if provider in {"anthropic", "claude"}:
        credential = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if not credential:
            # Fallback: setup/OAuth token from ANTHROPIC_TOKEN or ANTHROPIC_AUTH_TOKEN
            credential = (
                os.getenv("ANTHROPIC_TOKEN", "").strip()
                or os.getenv("ANTHROPIC_AUTH_TOKEN", "").strip()
            )
            if credential:
                auth_method = "setup_token"
        if not model:
            model = "claude-sonnet-4-5-20250514"
        if not api_base:
            api_base = DEFAULT_ANTHROPIC_BASE
    elif provider in {"openai", "openai-codex", "codex"}:
        credential = os.getenv("OPENAI_API_KEY", "").strip()
        if not model:
            model = "gpt-4o"
        if not api_base:
            api_base = DEFAULT_OPENAI_BASE
    elif provider in {"google-antigravity"}:
        credential = os.getenv("GOOGLE_ANTIGRAVITY_TOKEN", "").strip()
        if credential:
            auth_method = "oauth_token"
        if not api_base:
            api_base = DEFAULT_PROVIDER_BASES.get("google-antigravity", "")
    elif provider in {"google-gemini-cli"}:
        credential = os.getenv("GOOGLE_GEMINI_CLI_TOKEN", "").strip()
        if credential:
            auth_method = "oauth_token"
        if not api_base:
            api_base = DEFAULT_PROVIDER_BASES.get("google-gemini-cli", "")
    elif provider in {"lmstudio", "lm-studio", "ollama"}:
        # Local LLM providers don't require API credentials
        credential = os.getenv("LLM_LOCAL_API_KEY", "fake_key").strip()
        if not model:
            model = "qwen/qwen3-coder-next"
        if not api_base:
            api_base = DEFAULT_PROVIDER_BASES.get(provider, "http://host.docker.internal:1234/v1")
    else:
        credential = os.getenv("ZHIPU_API_KEY", "").strip()
        if not model:
            model = "glm-4.7"
        if not api_base:
            api_base = DEFAULT_ZAI_BASE

    model = _normalize_model(provider, model)
    return {
        "provider_id": provider,
        "api_style": api_style,
        "api_base": api_base,
        "model": model,
        "auth_method": auth_method,
        "credential": credential,
        "source": "env",
    }


def _resolve_owner_provider_config(llm_settings: dict, provider_override: Optional[str] = None) -> dict:
    provider_id = (provider_override or llm_settings.get("default_provider") or "").strip().lower()
    if not provider_id:
        return {}
    providers = llm_settings.get("providers", {}) or {}
    cfg = providers.get(provider_id, {}) or {}
    if not cfg:
        return {"error": "provider_not_configured", "provider_id": provider_id}
    if not _is_enabled(cfg):
        return {"error": "provider_disabled", "provider_id": provider_id}
    encrypted = cfg.get("credential_encrypted")
    if not encrypted:
        return {"error": "provider_not_configured", "provider_id": provider_id}
    try:
        credential = decrypt_value(encrypted)
    except Exception:
        return {"error": "credential_decrypt_failed", "provider_id": provider_id}

    api_style = (cfg.get("api_style") or _infer_api_style(provider_id)).strip().lower()
    api_base = (cfg.get("api_base") or DEFAULT_PROVIDER_BASES.get(provider_id) or "").strip()
    model = (cfg.get("model") or os.getenv("LLM_MODEL", "") or "").strip()
    if not model:
        model = "glm-4.7" if provider_id in {"glm", "z.ai", "zai", "zhipu"} else "gpt-4o"
    model = _normalize_model(provider_id, model)
    return {
        "provider_id": provider_id,
        "api_style": api_style,
        "api_base": api_base,
        "model": model,
        "auth_method": cfg.get("auth_method") or "api_key",
        "credential": credential,
        "source": "owner",
    }

def _require_proxy_token(request: Request):
    token = os.getenv("LLM_PROXY_TOKEN", "").strip()
    if not token:
        # If not configured, we keep the endpoint effectively disabled.
        raise HTTPException(status_code=503, detail="LLM proxy is not configured")

    provided = (
        request.headers.get("X-LLM-Proxy-Token", "").strip()
        or request.headers.get("Authorization", "").replace("Bearer", "").strip()
    )
    if provided != token:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.post("/chat")
async def llm_chat(req: LLMChatRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Internal LLM chat completion endpoint."""

    _require_proxy_token(request)

    llm_settings = await _load_owner_llm_settings(db)
    thinking_level = (llm_settings.get("thinking_level") or os.getenv("LLM_THINKING_LEVEL", "")).strip().lower()

    provider_override = (req.provider_override or "").strip().lower() or None

    LOCAL_PROVIDERS = {"lmstudio", "lm-studio", "ollama"}

    # If .env specifies a local provider, use env config directly (skip owner DB)
    env_provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if env_provider in LOCAL_PROVIDERS and not provider_override:
        cfg = _resolve_env_provider_config()
    else:
        owner_cfg = _resolve_owner_provider_config(llm_settings, provider_override)
        if owner_cfg.get("error"):
            if provider_override and provider_override not in LOCAL_PROVIDERS:
                raise HTTPException(status_code=400, detail=f"LLM provider override error: {owner_cfg.get('error')}")
            if provider_override in LOCAL_PROVIDERS:
                # Local providers don't need owner DB config — fall through to env
                owner_cfg = {}
            else:
                raise HTTPException(status_code=500, detail=f"Owner LLM provider error: {owner_cfg.get('error')}")
        cfg = owner_cfg or _resolve_env_provider_config()
    provider_id = cfg.get("provider_id") or "unknown"
    api_style = cfg.get("api_style") or "openai"
    api_base = cfg.get("api_base") or ""
    model = cfg.get("model") or "glm-4.7"
    auth_method = (cfg.get("auth_method") or "api_key").lower()
    credential = cfg.get("credential") or ""

    # Allow Claude subscription setup-token fallback when no API key is configured.
    if not credential and provider_id in {"anthropic", "claude"}:
        subscription_token = await _load_owner_subscription_token(db)
        if subscription_token:
            credential = subscription_token
            auth_method = "setup_token"

    # Local LLM providers (LM Studio, Ollama) don't require real credentials
    if not credential and provider_id not in {"lmstudio", "lm-studio", "ollama"}:
        raise HTTPException(status_code=500, detail="LLM credential not configured")
    if not credential:
        credential = "fake_key"  # Local LLM placeholder

    messages = _apply_thinking(req.messages, thinking_level, provider_id)

    timeout_s = float(os.getenv("LLM_PROXY_TIMEOUT_SECONDS", "120"))
    max_attempts = int(os.getenv("LLM_PROXY_RETRY_MAX", "5"))
    base_backoff = float(os.getenv("LLM_PROXY_RETRY_BASE_SECONDS", "2"))

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_s)) as client:
        last_error: Optional[str] = None
        for attempt in range(1, max_attempts + 1):
            try:
                if api_style == "openai":
                    if not api_base:
                        raise HTTPException(status_code=500, detail="LLM API base not configured")
                    url = api_base.rstrip("/")
                    if not url.endswith("/chat/completions"):
                        url = f"{url}/chat/completions"

                    payload = {
                        "model": model,
                        "messages": messages,
                        "max_tokens": req.max_tokens,
                        "temperature": req.temperature,
                    }
                    headers = {
                        "Authorization": f"Bearer {credential}",
                        "Content-Type": "application/json",
                    }

                    resp = await asyncio.wait_for(
                        client.post(url, headers=headers, json=payload),
                        timeout=timeout_s,
                    )

                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict) and data.get("error"):
                            last_error = f"upstream_error: {data.get('error')}"
                            if attempt == max_attempts:
                                raise HTTPException(status_code=502, detail="LLM upstream returned error payload")
                            wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                            await asyncio.sleep(wait_time)
                            continue
                        choices = (data.get("choices") or []) if isinstance(data, dict) else []
                        content = None
                        if choices:
                            msg = choices[0].get("message", {})
                            content = msg.get("content")
                            # Fallback: reasoning models (e.g. GLM-4.7) may put output
                            # in reasoning_content when content is empty.
                            if not content and msg.get("reasoning_content"):
                                content = msg["reasoning_content"]
                        if not content:
                            last_error = "empty_content"
                            if attempt == max_attempts:
                                raise HTTPException(status_code=502, detail="LLM upstream returned empty content")
                            wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                            await asyncio.sleep(wait_time)
                            continue
                        usage = data.get("usage", {}) or {}
                        return {
                            "provider": provider_id,
                            "model": model,
                            "content": content,
                            "usage": {
                                "prompt_tokens": usage.get("prompt_tokens", 0),
                                "completion_tokens": usage.get("completion_tokens", 0),
                                "total_tokens": usage.get(
                                    "total_tokens",
                                    usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0),
                                ),
                            },
                        }

                elif api_style == "anthropic":
                    if not api_base:
                        api_base = DEFAULT_ANTHROPIC_BASE
                    url = api_base.rstrip("/")
                    if not url.endswith("/messages"):
                        url = f"{url}/messages"

                    # Convert OpenAI-style messages to Claude format
                    system_parts = []
                    claude_messages = []

                    # Setup tokens require Claude Code identity as first system block.
                    if _is_setup_token(credential):
                        system_parts.append({
                            "type": "text",
                            "text": "You are Claude Code, Anthropic's official CLI for Claude.",
                        })

                    for msg in messages:
                        if msg.get("role") == "system":
                            system_parts.append({
                                "type": "text",
                                "text": msg.get("content", ""),
                            })
                        else:
                            claude_messages.append({
                                "role": msg.get("role"),
                                "content": msg.get("content"),
                            })

                    payload = {
                        "model": model,
                        "messages": claude_messages,
                        "max_tokens": req.max_tokens,
                        "temperature": req.temperature,
                    }
                    if system_parts:
                        payload["system"] = system_parts

                    headers = {
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    }
                    if _is_setup_token(credential):
                        # Setup tokens require Bearer auth + Claude Code beta headers.
                        headers["Authorization"] = f"Bearer {credential}"
                        headers["anthropic-beta"] = "claude-code-20250219,oauth-2025-04-20"
                        headers["user-agent"] = "claude-cli/2.1.32 (external, cli)"
                        headers["x-app"] = "cli"
                    elif auth_method == "api_key":
                        headers["x-api-key"] = credential
                    else:
                        headers["Authorization"] = f"Bearer {credential}"

                    resp = await asyncio.wait_for(
                        client.post(url, headers=headers, json=payload),
                        timeout=timeout_s,
                    )

                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict) and data.get("error"):
                            last_error = f"upstream_error: {data.get('error')}"
                            if attempt == max_attempts:
                                raise HTTPException(status_code=502, detail="LLM upstream returned error payload")
                            wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                            await asyncio.sleep(wait_time)
                            continue
                        content_blocks = data.get("content") if isinstance(data, dict) else None
                        content = None
                        if isinstance(content_blocks, list) and content_blocks:
                            content = content_blocks[0].get("text")
                        if not content:
                            last_error = "empty_content"
                            if attempt == max_attempts:
                                raise HTTPException(status_code=502, detail="LLM upstream returned empty content")
                            wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                            await asyncio.sleep(wait_time)
                            continue
                        usage = data.get("usage", {}) or {}
                        return {
                            "provider": provider_id,
                            "model": model,
                            "content": content,
                            "usage": {
                                "prompt_tokens": usage.get("input_tokens", 0),
                                "completion_tokens": usage.get("output_tokens", 0),
                                "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                            },
                        }
                else:
                    raise HTTPException(status_code=400, detail=f"Unsupported LLM api_style: {api_style}")

                # Retry transient errors
                if resp.status_code in (429, 500, 502, 503, 504):
                    last_error = f"upstream {resp.status_code}"
                    if attempt == max_attempts:
                        # Preserve rate-limit semantics for callers so they can back off.
                        if resp.status_code == 429:
                            retry_after = resp.headers.get("retry-after")
                            headers = {"Retry-After": retry_after} if retry_after else None
                            raise HTTPException(
                                status_code=429,
                                detail="LLM upstream rate limited (429)",
                                headers=headers,
                            )
                        raise HTTPException(status_code=502, detail=f"LLM upstream error {resp.status_code}")
                    wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                    await asyncio.sleep(wait_time)
                    continue

                if resp.status_code == 401:
                    raise HTTPException(status_code=502, detail="LLM upstream unauthorized (check credentials)")

                raise HTTPException(status_code=502, detail=f"LLM upstream error {resp.status_code}")

            except asyncio.TimeoutError:
                last_error = "timeout"
                if attempt == max_attempts:
                    raise HTTPException(status_code=504, detail="LLM upstream timeout")
                wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                await asyncio.sleep(wait_time)
                continue

            except httpx.RequestError as e:
                last_error = f"request_error: {type(e).__name__}"
                if attempt == max_attempts:
                    raise HTTPException(status_code=502, detail="LLM upstream request error")
                wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                await asyncio.sleep(wait_time)
                continue

    raise HTTPException(status_code=502, detail=f"LLM proxy failed: {last_error or 'unknown'}")
