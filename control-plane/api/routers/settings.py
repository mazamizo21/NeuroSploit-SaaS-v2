"""
TazoSploit SaaS v2 - Settings Router
API key management and usage metering
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, extract
from sqlalchemy.orm.attributes import flag_modified
import structlog

from ..database import get_db
from ..models import Tenant, Job, JobStatus
from ..auth import get_current_user
from ..utils.crypto import encrypt_value, decrypt_value, mask_value

logger = structlog.get_logger()
router = APIRouter()

SAAS_OWNER_TENANT_ID = os.getenv("SAAS_OWNER_TENANT_ID", "a0000000-0000-0000-0000-000000000001")
SAAS_OWNER_EMAIL = os.getenv("SAAS_OWNER_EMAIL", "").strip().lower()


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ApiKeyRequest(BaseModel):
    api_key: str

class SubscriptionTokenRequest(BaseModel):
    token: str

class TokenStatusResponse(BaseModel):
    is_set: bool
    masked_token: Optional[str] = None
    is_valid: Optional[bool] = None

class ApiKeyStatusResponse(BaseModel):
    is_set: bool
    masked_key: Optional[str] = None
    is_valid: Optional[bool] = None
    last_tested: Optional[str] = None

class UsageJobBreakdown(BaseModel):
    job_id: str
    job_name: str
    phase: str
    tokens_used: int
    cost_usd: float
    created_at: str
    status: str

class MonthlyUsage(BaseModel):
    month: str
    tokens: int
    cost_usd: float
    job_count: int

class UsageResponse(BaseModel):
    total_tokens: int
    total_cost_usd: float
    total_jobs: int
    completed_jobs: int
    billing_period_start: str
    billing_period_end: str
    per_job: List[UsageJobBreakdown]
    monthly: List[MonthlyUsage]


class ExploitModeRequest(BaseModel):
    exploit_mode: str


class ExploitModeResponse(BaseModel):
    exploit_mode: str


ALLOWED_EXPLOIT_MODES = {"disabled", "explicit_only", "autonomous"}
ALLOWED_INTENSITIES = {"low", "medium", "high"}


class JobDefaultsRequest(BaseModel):
    default_intensity: Optional[str] = None
    default_timeout_seconds: Optional[int] = None


class JobDefaultsResponse(BaseModel):
    default_intensity: str
    default_timeout_seconds: int


class SupervisorSettingsRequest(BaseModel):
    enabled: Optional[bool] = None
    provider: Optional[str] = None  # supervisor LLM provider id


class SupervisorSettingsResponse(BaseModel):
    enabled: bool
    provider: Optional[str] = None


# =============================================================================
# LLM PROVIDER SETTINGS (SaaS Owner Only)
# =============================================================================

class LLMProviderUpdateRequest(BaseModel):
    auth_method: Optional[str] = None  # api_key | setup_token | oauth_token | bearer_token
    credential: Optional[str] = None
    api_style: Optional[str] = None  # openai | anthropic
    api_base: Optional[str] = None
    model: Optional[str] = None
    enabled: Optional[bool] = None
    clear: Optional[bool] = False


class LLMProviderStatus(BaseModel):
    provider_id: str
    is_set: bool
    masked_credential: Optional[str] = None
    auth_method: Optional[str] = None
    api_style: Optional[str] = None
    api_base: Optional[str] = None
    model: Optional[str] = None
    enabled: bool = False


class LLMSettingsUpdateRequest(BaseModel):
    default_provider: Optional[str] = None
    thinking_level: Optional[str] = None


class LLMSettingsResponse(BaseModel):
    default_provider: Optional[str] = None
    thinking_level: Optional[str] = None
    providers: dict[str, LLMProviderStatus] = Field(default_factory=dict)


class LLMOptionsResponse(BaseModel):
    default_provider: Optional[str] = None
    enabled_providers: List[str] = Field(default_factory=list)
    supervisor_enabled: bool = False
    supervisor_provider: Optional[str] = None


ALLOWED_THINKING_LEVELS = {"off", "minimal", "low", "medium", "high", "xhigh"}


def _normalize_thinking_level(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    normalized = value.strip().lower()
    aliases = {
        "none": "off",
        "disable": "off",
        "disabled": "off",
        "min": "minimal",
        "max": "xhigh",
        "highest": "xhigh",
        "ultra": "xhigh",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in ALLOWED_THINKING_LEVELS:
        return None
    return normalized


def _is_saas_owner(current_user) -> bool:
    if not current_user or getattr(current_user, "role", "") != "admin":
        return False
    tenant_match = True
    email_match = True
    if SAAS_OWNER_TENANT_ID:
        tenant_match = str(current_user.tenant_id) == SAAS_OWNER_TENANT_ID
    if SAAS_OWNER_EMAIL:
        email_match = (current_user.email or "").lower() == SAAS_OWNER_EMAIL
    return tenant_match and email_match


async def _load_owner_llm_settings(db: AsyncSession) -> dict:
    if not SAAS_OWNER_TENANT_ID:
        return {}
    try:
        owner_uuid = uuid.UUID(SAAS_OWNER_TENANT_ID)
    except Exception:
        return {}
    tenant = await db.get(Tenant, owner_uuid)
    if not tenant or not tenant.settings:
        return {}
    return tenant.settings.get("llm_settings", {}) or {}


def _is_enabled(cfg: dict) -> bool:
    if cfg is None:
        return False
    enabled = cfg.get("enabled")
    if enabled is None:
        return bool(cfg.get("credential_encrypted"))
    return bool(enabled)


def _enabled_providers(llm_settings: dict) -> List[str]:
    providers = (llm_settings or {}).get("providers", {}) or {}
    enabled = []
    for provider_id, cfg in providers.items():
        if _is_enabled(cfg):
            enabled.append(provider_id)
    return enabled

# =============================================================================
# API KEY ENDPOINTS
# =============================================================================

@router.post("/api-key")
async def save_api_key(
    data: ApiKeyRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Store encrypted API key for tenant"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    encrypted = encrypt_value(data.api_key)
    tenant.api_key_encrypted = encrypted
    await db.commit()

    logger.info("api_key_saved", tenant_id=str(tenant_id))
    return {"status": "saved", "masked_key": mask_value(data.api_key)}


@router.get("/api-key/status", response_model=ApiKeyStatusResponse)
async def get_api_key_status(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Check if API key is set and optionally valid"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    if not tenant.api_key_encrypted:
        return ApiKeyStatusResponse(is_set=False)

    try:
        decrypted = decrypt_value(tenant.api_key_encrypted)
        masked = mask_value(decrypted)
        return ApiKeyStatusResponse(is_set=True, masked_key=masked, is_valid=None)
    except Exception:
        return ApiKeyStatusResponse(is_set=True, is_valid=False)


@router.post("/api-key/test")
async def test_api_key(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Test if the stored API key is valid by calling Anthropic API"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant or not tenant.api_key_encrypted:
        raise HTTPException(status_code=400, detail="No API key set")

    try:
        decrypted = decrypt_value(tenant.api_key_encrypted)

        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": decrypted,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-5-20250514",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hi"}],
                },
                timeout=15.0,
            )
            if resp.status_code == 200:
                return {"valid": True, "message": "API key is valid"}
            elif resp.status_code == 401:
                return {"valid": False, "message": "Invalid API key"}
            else:
                return {"valid": False, "message": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"valid": False, "message": f"Test failed: {str(e)}"}


# =============================================================================
# LLM PROVIDER SETTINGS (SaaS Owner Only)
# =============================================================================

def _build_llm_settings_response(llm_settings: dict) -> LLMSettingsResponse:
    llm_settings = llm_settings or {}
    providers_raw = llm_settings.get("providers", {}) or {}
    providers: dict[str, LLMProviderStatus] = {}

    for provider_id, cfg in providers_raw.items():
        encrypted = cfg.get("credential_encrypted")
        masked = None
        is_set = False
        enabled = _is_enabled(cfg)
        if encrypted:
            try:
                masked = mask_value(decrypt_value(encrypted))
                is_set = True
            except Exception:
                is_set = True
        providers[provider_id] = LLMProviderStatus(
            provider_id=provider_id,
            is_set=is_set,
            masked_credential=masked,
            auth_method=cfg.get("auth_method"),
            api_style=cfg.get("api_style"),
            api_base=cfg.get("api_base"),
            model=cfg.get("model"),
            enabled=enabled,
        )

    return LLMSettingsResponse(
        default_provider=llm_settings.get("default_provider"),
        thinking_level=llm_settings.get("thinking_level"),
        providers=providers,
    )


@router.get("/llm/config", response_model=LLMSettingsResponse)
async def get_llm_config(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get SaaS owner LLM provider settings."""
    if not _is_saas_owner(current_user):
        raise HTTPException(status_code=403, detail="Owner access required")

    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    llm_settings = (tenant.settings or {}).get("llm_settings", {}) or {}
    return _build_llm_settings_response(llm_settings)


@router.post("/llm/config", response_model=LLMSettingsResponse)
async def update_llm_config(
    data: LLMSettingsUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Update SaaS owner LLM defaults (provider + thinking level)."""
    if not _is_saas_owner(current_user):
        raise HTTPException(status_code=403, detail="Owner access required")

    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = dict(tenant.settings or {})
    llm_settings = settings.get("llm_settings", {}) or {}

    if data.default_provider is not None:
        requested = data.default_provider.strip() if data.default_provider else ""
        if requested:
            enabled = _enabled_providers(llm_settings)
            if requested not in enabled:
                raise HTTPException(status_code=400, detail="Default provider must be enabled")
            llm_settings["default_provider"] = requested
        else:
            llm_settings["default_provider"] = None

    if data.thinking_level is not None:
        normalized = _normalize_thinking_level(data.thinking_level)
        if data.thinking_level and not normalized:
            raise HTTPException(status_code=400, detail="Invalid thinking level")
        llm_settings["thinking_level"] = normalized

    settings["llm_settings"] = llm_settings
    tenant.settings = settings
    flag_modified(tenant, "settings")
    await db.commit()

    logger.info(
        "llm_defaults_updated",
        tenant_id=str(tenant_id),
        default_provider=llm_settings.get("default_provider"),
        thinking_level=llm_settings.get("thinking_level"),
    )

    return _build_llm_settings_response(llm_settings)


@router.get("/llm/options", response_model=LLMOptionsResponse)
async def get_llm_options(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get enabled LLM providers and default for job-level selection."""
    if not SAAS_OWNER_TENANT_ID:
        return LLMOptionsResponse()
    try:
        owner_uuid = uuid.UUID(SAAS_OWNER_TENANT_ID)
    except Exception:
        return LLMOptionsResponse()
    tenant = await db.get(Tenant, owner_uuid)
    if not tenant or not tenant.settings:
        return LLMOptionsResponse()

    llm_settings = tenant.settings.get("llm_settings", {}) or {}
    supervisor_settings = tenant.settings.get("supervisor_settings", {}) or {}
    enabled = sorted(_enabled_providers(llm_settings))
    return LLMOptionsResponse(
        default_provider=llm_settings.get("default_provider"),
        enabled_providers=enabled,
        supervisor_enabled=bool(supervisor_settings.get("enabled", True)),
        supervisor_provider=supervisor_settings.get("provider"),
    )


@router.post("/llm/providers/{provider_id}", response_model=LLMProviderStatus)
async def upsert_llm_provider(
    provider_id: str,
    data: LLMProviderUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Set or update an LLM provider credential/config (owner-only)."""
    if not _is_saas_owner(current_user):
        raise HTTPException(status_code=403, detail="Owner access required")

    provider_id = (provider_id or "").strip().lower()
    if not provider_id:
        raise HTTPException(status_code=400, detail="Provider id required")

    allowed_auth_methods = {"api_key", "setup_token", "oauth_token", "bearer_token"}
    if data.auth_method and data.auth_method not in allowed_auth_methods:
        raise HTTPException(status_code=400, detail="Invalid auth method")

    allowed_api_styles = {"openai", "anthropic"}
    if data.api_style and data.api_style not in allowed_api_styles:
        raise HTTPException(status_code=400, detail="Invalid api style")

    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = dict(tenant.settings or {})
    llm_settings = settings.get("llm_settings", {}) or {}
    providers = llm_settings.get("providers", {}) or {}

    cfg = providers.get(provider_id, {}) or {}

    if data.clear:
        cfg.pop("credential_encrypted", None)
        if data.enabled is None:
            cfg["enabled"] = False

    if data.credential:
        cfg["credential_encrypted"] = encrypt_value(data.credential)
        if "enabled" not in cfg and data.enabled is None:
            cfg["enabled"] = True

    if data.auth_method is not None:
        cfg["auth_method"] = data.auth_method
    if data.api_style is not None:
        cfg["api_style"] = data.api_style
    if data.api_base is not None:
        cfg["api_base"] = data.api_base
    if data.model is not None:
        cfg["model"] = data.model
    if data.enabled is not None:
        cfg["enabled"] = bool(data.enabled)

    cfg["updated_at"] = datetime.utcnow().isoformat()

    if not cfg:
        providers.pop(provider_id, None)
    else:
        providers[provider_id] = cfg

    llm_settings["providers"] = providers
    settings["llm_settings"] = llm_settings
    tenant.settings = settings
    flag_modified(tenant, "settings")
    await db.commit()

    logger.info("llm_provider_updated", tenant_id=str(tenant_id), provider_id=provider_id)

    # Build status response
    encrypted = cfg.get("credential_encrypted") if cfg else None
    masked = None
    is_set = False
    enabled = _is_enabled(cfg)
    if encrypted:
        try:
            masked = mask_value(decrypt_value(encrypted))
            is_set = True
        except Exception:
            is_set = True

    return LLMProviderStatus(
        provider_id=provider_id,
        is_set=is_set,
        masked_credential=masked,
        auth_method=cfg.get("auth_method") if cfg else None,
        api_style=cfg.get("api_style") if cfg else None,
        api_base=cfg.get("api_base") if cfg else None,
        model=cfg.get("model") if cfg else None,
        enabled=enabled,
    )

# =============================================================================
# SUBSCRIPTION TOKEN ENDPOINTS
# =============================================================================

@router.post("/subscription-token")
async def save_subscription_token(
    data: SubscriptionTokenRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Store encrypted Claude subscription token for tenant"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    encrypted = encrypt_value(data.token)
    # Store in a dedicated column when available; fallback to api_key_encrypted prefix if needed.
    try:
        tenant.subscription_token_encrypted = encrypted
    except AttributeError:
        tenant.api_key_encrypted = f"TOKEN:{encrypted}"
    await db.commit()

    logger.info("subscription_token_saved", tenant_id=str(tenant_id))
    return {"status": "saved", "masked_token": mask_value(data.token)}


@router.get("/subscription-token/status", response_model=TokenStatusResponse)
async def get_subscription_token_status(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Check if subscription token is set"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    encrypted = None
    try:
        encrypted = getattr(tenant, 'subscription_token_encrypted', None)
    except Exception:
        pass

    # Check TOKEN: prefix fallback
    if not encrypted and tenant.api_key_encrypted and tenant.api_key_encrypted.startswith("TOKEN:"):
        encrypted = tenant.api_key_encrypted[6:]

    if not encrypted:
        return TokenStatusResponse(is_set=False)

    try:
        decrypted = decrypt_value(encrypted)
        masked = mask_value(decrypted)
        return TokenStatusResponse(is_set=True, masked_token=masked)
    except Exception:
        return TokenStatusResponse(is_set=True, is_valid=False)


@router.post("/subscription-token/test")
async def test_subscription_token(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Test if the stored subscription token is valid"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=400, detail="No subscription token set")

    encrypted = None
    try:
        encrypted = getattr(tenant, 'subscription_token_encrypted', None)
    except Exception:
        pass
    if not encrypted and tenant.api_key_encrypted and tenant.api_key_encrypted.startswith("TOKEN:"):
        encrypted = tenant.api_key_encrypted[6:]

    if not encrypted:
        raise HTTPException(status_code=400, detail="No subscription token set")

    try:
        decrypted = decrypt_value(encrypted)

        import httpx

        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": "claude-sonnet-4-5-20250929",
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "Hi"}],
        }

        if decrypted.startswith("sk-ant-oat"):
            # Setup tokens require Bearer auth + Claude Code beta headers.
            headers["Authorization"] = f"Bearer {decrypted}"
            headers["anthropic-beta"] = "claude-code-20250219,oauth-2025-04-20"
            headers["user-agent"] = "claude-cli/2.1.32 (external, cli)"
            headers["x-app"] = "cli"
            payload["system"] = [{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}]
        else:
            headers["x-api-key"] = decrypted

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
                timeout=15.0,
            )
            if resp.status_code == 200:
                return {"valid": True, "message": "Subscription token is valid"}
            elif resp.status_code == 401:
                return {"valid": False, "message": "Invalid or expired token. Run `claude setup-token` again."}
            else:
                return {"valid": False, "message": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"valid": False, "message": f"Test failed: {str(e)}"}


# =============================================================================
# DEFAULT EXPLOIT MODE ENDPOINTS
# =============================================================================

@router.get("/exploit-mode", response_model=ExploitModeResponse)
async def get_exploit_mode(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get the tenant default exploit mode"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = dict(tenant.settings or {})
    exploit_mode = settings.get("default_exploit_mode", "explicit_only")
    if exploit_mode not in ALLOWED_EXPLOIT_MODES:
        exploit_mode = "explicit_only"
    return ExploitModeResponse(exploit_mode=exploit_mode)


@router.post("/exploit-mode", response_model=ExploitModeResponse)
async def set_exploit_mode(
    data: ExploitModeRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Set the tenant default exploit mode"""
    exploit_mode = (data.exploit_mode or "").lower()
    if exploit_mode not in ALLOWED_EXPLOIT_MODES:
        raise HTTPException(status_code=400, detail="Invalid exploit mode")

    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = dict(tenant.settings or {})
    settings["default_exploit_mode"] = exploit_mode
    tenant.settings = settings
    flag_modified(tenant, "settings")
    await db.commit()

    logger.info("exploit_mode_updated", tenant_id=str(tenant_id), exploit_mode=exploit_mode)
    return ExploitModeResponse(exploit_mode=exploit_mode)


# =============================================================================
# DEFAULT JOB SETTINGS ENDPOINTS
# =============================================================================

@router.get("/job-defaults", response_model=JobDefaultsResponse)
async def get_job_defaults(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get tenant defaults for job settings"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = dict(tenant.settings or {})
    default_intensity = settings.get("default_intensity", "medium")
    default_timeout_seconds = settings.get("default_timeout_seconds", 3600)

    if default_intensity not in ALLOWED_INTENSITIES:
        default_intensity = "medium"
    try:
        default_timeout_seconds = int(default_timeout_seconds)
    except Exception:
        default_timeout_seconds = 3600
    if default_timeout_seconds < 60 or default_timeout_seconds > 14400:
        default_timeout_seconds = 3600

    return JobDefaultsResponse(
        default_intensity=default_intensity,
        default_timeout_seconds=default_timeout_seconds
    )


@router.post("/job-defaults", response_model=JobDefaultsResponse)
async def set_job_defaults(
    data: JobDefaultsRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Set tenant defaults for job settings"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = dict(tenant.settings or {})

    if data.default_intensity:
        intensity = data.default_intensity.lower()
        if intensity not in ALLOWED_INTENSITIES:
            raise HTTPException(status_code=400, detail="Invalid default intensity")
        settings["default_intensity"] = intensity

    if data.default_timeout_seconds is not None:
        if data.default_timeout_seconds < 60 or data.default_timeout_seconds > 14400:
            raise HTTPException(status_code=400, detail="Default timeout must be between 60 and 14400 seconds")
        settings["default_timeout_seconds"] = int(data.default_timeout_seconds)

    tenant.settings = settings
    flag_modified(tenant, "settings")
    await db.commit()

    logger.info(
        "job_defaults_updated",
        tenant_id=str(tenant_id),
        default_intensity=settings.get("default_intensity", "medium"),
        default_timeout_seconds=settings.get("default_timeout_seconds", 3600),
    )

    return JobDefaultsResponse(
        default_intensity=settings.get("default_intensity", "medium"),
        default_timeout_seconds=settings.get("default_timeout_seconds", 3600),
    )


# =============================================================================
# SUPERVISOR SETTINGS (OWNER ONLY)
# =============================================================================

@router.get("/supervisor", response_model=SupervisorSettingsResponse)
async def get_supervisor_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not _is_saas_owner(current_user):
        raise HTTPException(status_code=403, detail="Owner access required")

    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = dict(tenant.settings or {})
    supervisor_settings = settings.get("supervisor_settings", {}) or {}
    enabled = supervisor_settings.get("enabled")
    if enabled is None:
        enabled = True
    provider = supervisor_settings.get("provider")

    try:
        await request.app.state.redis.set("supervisor:enabled", "true" if enabled else "false")
        if provider:
            await request.app.state.redis.set("supervisor:provider", provider)
        else:
            await request.app.state.redis.delete("supervisor:provider")
    except Exception:
        pass

    return SupervisorSettingsResponse(enabled=bool(enabled), provider=provider)


@router.post("/supervisor", response_model=SupervisorSettingsResponse)
async def update_supervisor_settings(
    data: SupervisorSettingsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not _is_saas_owner(current_user):
        raise HTTPException(status_code=403, detail="Owner access required")

    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = dict(tenant.settings or {})
    supervisor_settings = settings.get("supervisor_settings", {}) or {}

    if data.enabled is not None:
        supervisor_settings["enabled"] = bool(data.enabled)

    if "enabled" not in supervisor_settings:
        supervisor_settings["enabled"] = True

    if data.provider is not None:
        supervisor_settings["provider"] = data.provider.strip().lower() if data.provider.strip() else None

    settings["supervisor_settings"] = supervisor_settings
    tenant.settings = settings
    flag_modified(tenant, "settings")
    await db.commit()

    enabled = bool(supervisor_settings.get("enabled", True))
    provider = supervisor_settings.get("provider")

    try:
        await request.app.state.redis.set("supervisor:enabled", "true" if enabled else "false")
        if provider:
            await request.app.state.redis.set("supervisor:provider", provider)
        else:
            await request.app.state.redis.delete("supervisor:provider")
    except Exception:
        pass

    logger.info("supervisor_settings_updated", tenant_id=str(tenant_id), enabled=enabled, provider=provider)
    return SupervisorSettingsResponse(enabled=enabled, provider=provider)


# =============================================================================
# USAGE METERING ENDPOINTS
# =============================================================================

@router.get("/usage", response_model=UsageResponse)
async def get_usage(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get usage statistics for the current tenant"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id

    # Billing period: 1st of current month to last day
    now = datetime.utcnow()
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if now.month == 12:
        period_end = now.replace(year=now.year + 1, month=1, day=1) - timedelta(seconds=1)
    else:
        period_end = now.replace(month=now.month + 1, day=1) - timedelta(seconds=1)

    # Get all jobs for tenant
    result = await db.execute(
        select(Job).where(Job.tenant_id == tenant_id).order_by(Job.created_at.desc())
    )
    jobs = result.scalars().all()

    total_tokens = sum(j.tokens_used or 0 for j in jobs)
    total_cost_cents = sum(j.cost_usd or 0 for j in jobs)
    completed = sum(1 for j in jobs if j.status == JobStatus.completed)

    # Per-job breakdown
    per_job = []
    for j in jobs[:50]:  # last 50
        per_job.append(UsageJobBreakdown(
            job_id=str(j.id),
            job_name=j.name,
            phase=j.phase,
            tokens_used=j.tokens_used or 0,
            cost_usd=(j.cost_usd or 0) / 100,
            created_at=j.created_at.isoformat() if j.created_at else "",
            status=j.status.value if hasattr(j.status, 'value') else str(j.status),
        ))

    # Monthly aggregation (last 6 months)
    monthly = []
    for i in range(6):
        m = now.month - i
        y = now.year
        if m <= 0:
            m += 12
            y -= 1
        month_start = datetime(y, m, 1)
        if m == 12:
            month_end = datetime(y + 1, 1, 1)
        else:
            month_end = datetime(y, m + 1, 1)

        month_jobs = [j for j in jobs if j.created_at and month_start <= j.created_at < month_end]
        month_tokens = sum(j.tokens_used or 0 for j in month_jobs)
        month_cost = sum(j.cost_usd or 0 for j in month_jobs)

        monthly.append(MonthlyUsage(
            month=month_start.strftime("%Y-%m"),
            tokens=month_tokens,
            cost_usd=month_cost / 100,
            job_count=len(month_jobs),
        ))

    monthly.reverse()

    return UsageResponse(
        total_tokens=total_tokens,
        total_cost_usd=total_cost_cents / 100,
        total_jobs=len(jobs),
        completed_jobs=completed,
        billing_period_start=period_start.isoformat(),
        billing_period_end=period_end.isoformat(),
        per_job=per_job,
        monthly=monthly,
    )
