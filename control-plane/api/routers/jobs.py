"""
TazoSploit SaaS v2 - Jobs Router
Job creation, management, and execution control
"""

import json
import os
import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
import structlog

from ..database import get_db
from ..utils.redact import redact_obj, redact_text
from ..models import Job, JobStatus, Scope, Tenant, AuditLog, Finding
from ..auth import get_current_user, require_permission

logger = structlog.get_logger()
router = APIRouter()
ALLOWED_EXPLOIT_MODES = {"disabled", "explicit_only", "autonomous"}
SAAS_OWNER_TENANT_ID = os.getenv("SAAS_OWNER_TENANT_ID", "a0000000-0000-0000-0000-000000000001")


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


LOCAL_PROVIDERS = {"lmstudio", "lm-studio", "ollama"}


def _enabled_providers(llm_settings: dict) -> set[str]:
    providers = (llm_settings or {}).get("providers", {}) or {}
    enabled = set()
    for provider_id, cfg in providers.items():
        flag = cfg.get("enabled")
        if flag is None:
            flag = bool(cfg.get("credential_encrypted"))
        if flag:
            enabled.add(provider_id)
    # Always allow local providers and the env-configured provider
    enabled |= LOCAL_PROVIDERS
    env_provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if env_provider:
        enabled.add(env_provider)
    return enabled

# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class JobCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scope_id: str  # N3: validated as UUID below in create_job()
    phase: str = Field(..., pattern="^(RECON|VULN_SCAN|EXPLOIT|POST_EXPLOIT|REPORT|FULL|LATERAL)$")
    targets: List[str]
    intensity: Optional[str] = Field(default=None, pattern="^(low|medium|high)$")
    timeout_seconds: Optional[int] = Field(default=None, ge=60, le=172800)
    auto_run: bool = False
    target_type: str = Field(default="lab", pattern="^(lab|external)$")
    authorization_confirmed: bool = False
    exploit_mode: Optional[str] = Field(default=None, pattern="^(disabled|explicit_only|autonomous)$")
    max_iterations: int = Field(default=30, ge=0, le=99999)  # 0 = unlimited
    llm_provider: Optional[str] = None  # Optional per-job provider override
    llm_profile: Optional[str] = Field(default=None, pattern="^(strict|balanced|relaxed|unleashed|unhinged)$")  # Agent profile
    agent_freedom: Optional[int] = Field(default=None, ge=1, le=10)  # Agent freedom level (1-10)
    supervisor_enabled: Optional[bool] = None   # None = use global default
    supervisor_provider: Optional[str] = None   # None = use global default
    allow_persistence: Optional[bool] = None
    allow_defense_evasion: Optional[bool] = None
    allow_scope_expansion: Optional[bool] = None
    enable_session_handoff: Optional[bool] = None
    enable_target_rotation: Optional[bool] = None
    target_focus_window: Optional[int] = Field(default=None, ge=2, le=50)
    target_focus_limit: Optional[int] = Field(default=None, ge=5, le=5000)
    target_min_commands: Optional[int] = Field(default=None, ge=1, le=500)

class JobResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    scope_id: Optional[str]
    phase: str
    targets: List[str]
    target_type: str = "lab"
    intensity: Optional[str] = None
    timeout_seconds: Optional[int] = None
    max_iterations: int = 30
    authorization_confirmed: bool = False
    exploit_mode: str = "explicit_only"
    llm_provider: Optional[str] = None
    llm_profile: Optional[str] = None
    agent_freedom: Optional[int] = None
    supervisor_enabled: Optional[bool] = None
    supervisor_provider: Optional[str] = None
    allow_persistence: bool = False
    allow_defense_evasion: bool = False
    allow_scope_expansion: bool = False
    enable_session_handoff: bool = False
    enable_target_rotation: bool = True
    target_focus_window: int = 6
    target_focus_limit: int = 30
    target_min_commands: int = 8
    status: str
    progress: int
    findings_count: int
    critical_count: int
    high_count: int
    tokens_used: int
    cost_usd: float
    worker_id: Optional[str] = None
    container_id: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    result: Optional[dict] = None

class JobListResponse(BaseModel):
    jobs: List[JobResponse]
    total: int
    page: int
    page_size: int

# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("", response_model=JobResponse)
async def create_job(
    job_data: JobCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new pentest job"""
    
    tenant_id = current_user.tenant_id
    tenant_uuid = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id
    
    # N3: Validate scope_id is a well-formed UUID before any DB operations
    import re as _re_uuid
    if job_data.target_type != "external":
        try:
            uuid.UUID(job_data.scope_id)
        except (ValueError, AttributeError):
            raise HTTPException(status_code=400, detail="scope_id must be a valid UUID")
    
    logger.info(
        "job_create_started",
        tenant_id=str(tenant_id),
        phase=job_data.phase,
        targets=job_data.targets
    )
    tenant = await db.get(Tenant, tenant_uuid)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    settings = tenant.settings or {}
    default_exploit_mode = settings.get("default_exploit_mode", "explicit_only")
    exploit_mode = (job_data.exploit_mode or default_exploit_mode or "explicit_only").lower()
    if exploit_mode not in ALLOWED_EXPLOIT_MODES:
        exploit_mode = "explicit_only"

    if exploit_mode == "disabled" and job_data.phase in ("EXPLOIT", "POST_EXPLOIT", "LATERAL", "FULL"):
        raise HTTPException(
            status_code=400,
            detail="Exploit mode is disabled. Choose a non-exploit phase or enable exploitation."
        )

    default_intensity = settings.get("default_intensity", "medium")
    effective_intensity = (job_data.intensity or default_intensity or "medium").lower()

    default_timeout = settings.get("default_timeout_seconds", 3600)
    effective_timeout = job_data.timeout_seconds if job_data.timeout_seconds is not None else default_timeout
    try:
        effective_timeout = int(effective_timeout)
    except Exception:
        effective_timeout = 3600
    if effective_timeout < 60 or effective_timeout > 172800:
        raise HTTPException(status_code=400, detail="Timeout must be between 60 and 172800 seconds (48h max)")

    llm_settings = None
    llm_provider_override = (job_data.llm_provider or "").strip().lower()
    supervisor_provider_override = (job_data.supervisor_provider or "").strip().lower()

    # Default to the SaaS owner's configured provider if the caller didn't specify one.
    # This makes "use GLM-5 via Z.AI" deterministic for every job without requiring the UI
    # to always send `llm_provider`.
    if not llm_provider_override:
        llm_settings = await _load_owner_llm_settings(db)
        default_provider = (llm_settings.get("default_provider") or "").strip().lower()
        if default_provider:
            llm_provider_override = default_provider

    if llm_provider_override or supervisor_provider_override:
        if llm_settings is None:
            llm_settings = await _load_owner_llm_settings(db)
        enabled = _enabled_providers(llm_settings)
        if llm_provider_override and llm_provider_override not in enabled:
            raise HTTPException(status_code=400, detail="LLM provider is not enabled")
        if supervisor_provider_override and supervisor_provider_override not in enabled:
            raise HTTPException(status_code=400, detail="Supervisor LLM provider is not enabled")

    # Handle external targets — create ad-hoc scope or skip scope validation
    if job_data.target_type == "external":
        if not job_data.authorization_confirmed:
            raise HTTPException(
                status_code=400,
                detail="Authorization confirmation required for external targets"
            )
        
        # For external targets, create an ad-hoc scope automatically
        scope = Scope(
            tenant_id=tenant_uuid,
            name=f"External: {', '.join(job_data.targets[:3])}",
            description=f"Auto-created scope for external target scan",
            targets=job_data.targets,
            excluded_targets=[],
            authorization_type="customer_authorized",
            allowed_phases=["RECON", "VULN_SCAN", "EXPLOIT", "POST_EXPLOIT", "REPORT", "FULL", "LATERAL"],
            max_intensity="high",
            is_active=True,
        )
        db.add(scope)
        await db.flush()
        
        logger.info(
            "external_scope_created",
            scope_id=str(scope.id),
            targets=job_data.targets,
            tenant_id=str(tenant_id)
        )
    else:
        # Verify scope exists and belongs to tenant
        scope = await db.get(Scope, uuid.UUID(job_data.scope_id))
        if not scope or scope.tenant_id != tenant_uuid:
            raise HTTPException(status_code=404, detail="Scope not found")
        
        if not scope.is_active:
            raise HTTPException(status_code=400, detail="Scope is not active")
        
        # Verify targets are within scope
        for target in job_data.targets:
            if not _target_in_scope(target, scope.targets, scope.excluded_targets):
                raise HTTPException(
                    status_code=400, 
                    detail=f"Target '{target}' is not within approved scope"
                )
    
    # Check phase is allowed for scope
    if job_data.phase not in scope.allowed_phases:
        raise HTTPException(
            status_code=400,
            detail=f"Phase '{job_data.phase}' not allowed for this scope"
        )
    
    # Check intensity limit
    intensity_order = {"low": 1, "medium": 2, "high": 3}
    if effective_intensity not in intensity_order:
        raise HTTPException(status_code=400, detail="Invalid intensity value")
    if intensity_order.get(effective_intensity, 0) > intensity_order.get(scope.max_intensity, 2):
        raise HTTPException(
            status_code=400,
            detail=f"Intensity '{effective_intensity}' exceeds scope limit '{scope.max_intensity}'"
        )
    
    # Check tenant quotas
    running_jobs = await db.execute(
        select(Job).where(
            and_(
                Job.tenant_id == tenant_uuid,
                Job.status.in_([JobStatus.pending, JobStatus.queued, JobStatus.running])
            )
        )
    )
    if len(running_jobs.scalars().all()) >= tenant.max_concurrent_jobs:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum concurrent jobs ({tenant.max_concurrent_jobs}) reached"
        )
    
    # Create job (0 = unlimited → 99999)
    effective_iterations = job_data.max_iterations if job_data.max_iterations > 0 else 99999

    allow_scope_expansion = job_data.allow_scope_expansion
    if allow_scope_expansion is None:
        allow_scope_expansion = job_data.target_type == "lab"
    enable_session_handoff = job_data.enable_session_handoff
    if enable_session_handoff is None:
        enable_session_handoff = job_data.target_type == "lab"
    allow_persistence = bool(job_data.allow_persistence) if job_data.allow_persistence is not None else False
    allow_defense_evasion = bool(job_data.allow_defense_evasion) if job_data.allow_defense_evasion is not None else False
    enable_target_rotation = bool(job_data.enable_target_rotation) if job_data.enable_target_rotation is not None else True
    target_focus_window = job_data.target_focus_window if job_data.target_focus_window is not None else 6
    target_focus_limit = job_data.target_focus_limit if job_data.target_focus_limit is not None else 30
    target_min_commands = job_data.target_min_commands if job_data.target_min_commands is not None else 8

    if job_data.target_type == "external" and not job_data.authorization_confirmed:
        allow_persistence = False
        allow_defense_evasion = False
        allow_scope_expansion = False
        enable_session_handoff = False
    
    job = Job(
        tenant_id=tenant_uuid,
        scope_id=scope.id,
        created_by=uuid.UUID(current_user.id),
        name=job_data.name,
        description=job_data.description,
        phase=job_data.phase,
        targets=job_data.targets,
        target_type=job_data.target_type,
        intensity=effective_intensity,
        timeout_seconds=effective_timeout,
        auto_run=job_data.auto_run,
        max_iterations=effective_iterations,
        authorization_confirmed=bool(job_data.authorization_confirmed),
        exploit_mode=exploit_mode,
        llm_provider=llm_provider_override or None,
        llm_profile=job_data.llm_profile,
        agent_freedom=job_data.agent_freedom,
        supervisor_enabled=job_data.supervisor_enabled,
        supervisor_provider=supervisor_provider_override or None,
        allow_persistence=allow_persistence,
        allow_defense_evasion=allow_defense_evasion,
        allow_scope_expansion=bool(allow_scope_expansion),
        enable_session_handoff=bool(enable_session_handoff),
        enable_target_rotation=bool(enable_target_rotation),
        target_focus_window=int(target_focus_window),
        target_focus_limit=int(target_focus_limit),
        target_min_commands=int(target_min_commands),
        status=JobStatus.pending
    )
    
    db.add(job)
    await db.flush()
    
    # Audit log
    audit = AuditLog(
        tenant_id=tenant_uuid,
        user_id=uuid.UUID(current_user.id),
        action="job.create",
        resource_type="job",
        resource_id=job.id,
        request_id=request.headers.get("X-Request-ID"),
        ip_address=request.client.host if request.client else None,
        changes={"created": job_data.dict()}
    )
    db.add(audit)
    
    await db.commit()
    
    # Queue job for execution (via Redis)
    redis = request.app.state.redis
    await redis.lpush(
        f"tenant:{tenant_id}:job_queue",
        str(job.id)
    )

    # Set per-job supervisor overrides in Redis (24h TTL)
    if job_data.supervisor_enabled is not None:
        await redis.set(
            f"job:{job.id}:supervisor_enabled",
            "true" if job_data.supervisor_enabled else "false",
            ex=86400,
        )
    if supervisor_provider_override:
        await redis.set(
            f"job:{job.id}:supervisor_provider",
            supervisor_provider_override,
            ex=86400,
        )

    logger.info(
        "job_created",
        job_id=str(job.id),
        tenant_id=str(tenant_id),
        phase=job_data.phase
    )
    
    return _job_to_response(job)


@router.get("", response_model=JobListResponse)
async def list_jobs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    phase: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List jobs for current tenant"""
    
    tenant_id = current_user.tenant_id
    tenant_uuid = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id
    
    query = select(Job).where(Job.tenant_id == tenant_uuid)
    
    if status:
        query = query.where(Job.status == status)
    if phase:
        query = query.where(Job.phase == phase)
    
    query = query.order_by(Job.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(query)
    jobs = result.scalars().all()
    
    # Get total count
    count_query = select(Job).where(Job.tenant_id == tenant_uuid)
    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())
    
    return JobListResponse(
        jobs=[_job_to_response(j) for j in jobs],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get job details"""
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")
    
    return _job_to_response(job)


@router.post("/{job_id}/resume")
async def resume_job(
    job_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Resume a completed/failed/cancelled job from where it left off"""
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status not in [JobStatus.completed, JobStatus.failed, JobStatus.cancelled, JobStatus.timeout]:
        raise HTTPException(status_code=400, detail=f"Cannot resume a {job.status.value} job. Only completed/failed/cancelled/timed-out jobs can be resumed.")
    
    tenant_id = current_user.tenant_id
    tenant_uuid = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id
    
    # Check concurrent job limits
    tenant = await db.get(Tenant, tenant_uuid)
    running_jobs = await db.execute(
        select(Job).where(
            and_(
                Job.tenant_id == tenant_uuid,
                Job.status.in_([JobStatus.pending, JobStatus.queued, JobStatus.running])
            )
        )
    )
    if len(running_jobs.scalars().all()) >= tenant.max_concurrent_jobs:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum concurrent jobs ({tenant.max_concurrent_jobs}) reached"
        )
    
    # Store the previous iteration count so we know where to resume from
    prev_result = job.result or {}
    prev_iterations = prev_result.get("iterations", 0)

    # Reset job status to pending for re-execution
    job.status = JobStatus.pending
    # Clear stale result/output from the previous run; otherwise the UI may show
    # "ENGAGEMENT COMPLETE" while the resumed job is actually running.
    job.result = None
    # Allow the worker to set a fresh start time and assignment on re-dispatch
    job.started_at = None
    job.worker_id = None
    job.container_id = None
    job.completed_at = None
    job.error_message = None
    job.progress = 0
    
    # Audit log
    audit = AuditLog(
        tenant_id=tenant_uuid,
        user_id=uuid.UUID(current_user.id),
        action="job.resume",
        resource_type="job",
        resource_id=job.id,
        request_id=request.headers.get("X-Request-ID"),
        ip_address=request.client.host if request.client else None,
        changes={"resumed_from_iteration": prev_iterations}
    )
    db.add(audit)
    
    await db.commit()
    
    # Queue job for execution with resume flag
    redis = request.app.state.redis
    # Clear terminal flag set by the worker/scheduler; otherwise dispatch will be skipped.
    try:
        await redis.delete(f"job:{job_id}:terminal")
    except Exception:
        pass
    await redis.lpush(
        f"tenant:{tenant_id}:job_queue",
        str(job.id)
    )
    # Set a Redis key so the worker knows to resume
    await redis.set(f"job:{job_id}:resume", "true", ex=86400)
    
    logger.info("job_resumed", job_id=job_id, from_iteration=prev_iterations)
    
    return {"status": "resumed", "job_id": job_id, "resumed_from_iteration": prev_iterations}


@router.post("/{job_id}/cancel")
async def cancel_job(
    job_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Cancel a running job (kill switch)"""
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status not in [JobStatus.pending, JobStatus.queued, JobStatus.running]:
        raise HTTPException(status_code=400, detail="Job cannot be cancelled")
    
    # Send kill signal via Redis
    redis = request.app.state.redis
    await redis.publish(f"job:{job_id}:control", "CANCEL")
    
    job.status = JobStatus.cancelled
    job.completed_at = datetime.utcnow()
    
    # Audit log
    audit = AuditLog(
        tenant_id=uuid.UUID(current_user.tenant_id),
        user_id=uuid.UUID(current_user.id),
        action="job.cancel",
        resource_type="job",
        resource_id=job.id,
        request_id=request.headers.get("X-Request-ID"),
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    
    await db.commit()
    
    logger.info("job_cancelled", job_id=job_id, user_id=str(current_user.id))
    
    return {"status": "cancelled", "job_id": job_id}


class JobUpdate(BaseModel):
    status: Optional[str] = None
    progress: Optional[int] = None
    findings_count: Optional[int] = None
    critical_count: Optional[int] = None
    high_count: Optional[int] = None
    tokens_used: Optional[int] = None
    cost_usd: Optional[float] = None
    worker_id: Optional[str] = None
    container_id: Optional[str] = None
    error_message: Optional[str] = None
    result: Optional[dict] = None


@router.patch("/{job_id}", response_model=JobResponse)
async def update_job(
    job_id: str,
    update: JobUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update job status (used by workers)"""
    job = await db.get(Job, uuid.UUID(job_id))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if update.status:
        status_map = {s.value: s for s in JobStatus}
        if update.status in status_map:
            job.status = status_map[update.status]
            if update.status == "running" and not job.started_at:
                job.started_at = datetime.utcnow()
            elif update.status in ("completed", "failed", "cancelled"):
                job.completed_at = datetime.utcnow()

    if update.progress is not None:
        job.progress = update.progress
    if update.findings_count is not None:
        job.findings_count = update.findings_count
    if update.critical_count is not None:
        job.critical_count = update.critical_count
    if update.high_count is not None:
        job.high_count = update.high_count
    if update.tokens_used is not None:
        job.tokens_used = update.tokens_used
    if update.cost_usd is not None:
        job.cost_usd = int(update.cost_usd * 100)  # Store as cents (column is Integer)
    if update.worker_id is not None:
        job.worker_id = update.worker_id
    if update.container_id is not None:
        job.container_id = update.container_id
    if update.error_message is not None:
        job.error_message = redact_text(update.error_message)

    # Process result data from worker
    if update.result:
        # Redact secrets defensively before persisting
        safe_result = redact_obj(update.result)

        # Store the full result JSON
        job.result = safe_result
        # NOTE: Do not derive job counts from the result payload. Counts are derived
        # from persisted findings (verified-only) to avoid duplicates and tentative leads.
        
        # Extract token usage from result
        llm_stats = safe_result.get("llm_stats", {})
        tokens_from_result = safe_result.get("tokens_used", 0) or llm_stats.get("total_tokens", 0)
        cost_from_result = safe_result.get("cost_usd", 0.0) or llm_stats.get("total_cost_usd", 0.0)

        if tokens_from_result > 0:
            job.tokens_used = tokens_from_result
        if cost_from_result > 0:
            job.cost_usd = int(cost_from_result * 100)  # Store as cents

        if safe_result.get("error"):
            job.error_message = redact_text(str(safe_result["error"]))

    # Recompute counts from verified findings when a job reaches a terminal state.
    # This prevents PATCH-result payloads from overwriting deduped/verified-only counts.
    try:
        if update.status in ("completed", "failed", "cancelled", "timeout"):
            from ..models import Finding

            count_result = await db.execute(
                select(Finding.severity).where(
                    Finding.job_id == job.id,
                    Finding.verified.is_(True),
                    Finding.is_false_positive.is_(False),
                )
            )
            final_sevs = [
                row[0].value if hasattr(row[0], "value") else str(row[0])
                for row in count_result.fetchall()
            ]
            job.findings_count = len(final_sevs)
            job.critical_count = final_sevs.count("critical")
            job.high_count = final_sevs.count("high")
    except Exception:
        pass

    await db.commit()
    await db.refresh(job)

    return _job_to_response(job)


class FindingCreate(BaseModel):
    title: Optional[str] = None  # Auto-generated if not provided
    description: Optional[str] = None
    severity: str = "info"
    finding_type: Optional[str] = None
    type: Optional[str] = None  # Alias for finding_type (agent compat)
    location: Optional[str] = None  # Alias for target (agent compat)
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    target: Optional[str] = None
    evidence: Optional[str] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    # Worker/agent may send these to distinguish tentative leads from proven findings.
    verified: Optional[bool] = None
    is_false_positive: Optional[bool] = None
    
    def get_title(self) -> str:
        """Generate title from available fields if not provided"""
        if self.title:
            return self.title
        # Build title from type + severity + location
        ftype = self.finding_type or self.type or "Finding"
        loc = self.target or self.location or ""
        sev = self.severity.upper() if self.severity else ""
        if loc:
            return f"{sev} {ftype} at {loc}".strip()
        return f"{sev} {ftype}".strip() or "Untitled Finding"
    
    def get_finding_type(self) -> Optional[str]:
        """Get finding_type, falling back to type alias"""
        return self.finding_type or self.type
    
    def get_target(self) -> Optional[str]:
        """Get target, falling back to location alias"""
        return self.target or self.location


@router.post("/{job_id}/findings")
async def create_findings(
    job_id: str,
    findings: List[FindingCreate],
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Bulk create findings for a job (used by workers)"""
    from ..models import Finding, Severity
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    tenant_id = job.tenant_id
    created = []
    
    severity_map = {s.value: s for s in Severity}
    
    # 🐛 FIX: Dedup — fetch existing findings for this job (upsert: update if evidence/severity changed)
    from sqlalchemy import select
    existing_result = await db.execute(
        select(Finding).where(Finding.job_id == job.id)
    )
    existing_findings = existing_result.scalars().all()

    def _evidence_key(ev: Optional[str]) -> str:
        if not ev:
            return ""
        ev = str(ev).strip()
        ev_lower = ev.lower()
        if ev_lower in {"unknown", "n/a", "none"} or ev_lower.startswith("credentials: unknown"):
            return ""
        # Keep key small and stable even if evidence grows.
        return ev[:200]

    def _dedup_key(title: str, ftype: Optional[str], target: Optional[str], evidence: Optional[str]) -> tuple[str, str, str, str]:
        return (
            str(title or ""),
            str(ftype or ""),
            str(target or ""),
            _evidence_key(evidence),
        )

    existing_by_key = {
        _dedup_key(f.title, f.finding_type, f.target, f.evidence): f
        for f in existing_findings
        if isinstance(f, Finding)
    }
    existing_keys = set(existing_by_key.keys())
    skipped = 0
    updated = 0
    
    for f_data in findings:
        sev = severity_map.get(f_data.severity, Severity.info)
        # Use helper methods for agent compatibility
        title = f_data.get_title()
        finding_type = f_data.get_finding_type()
        target = f_data.get_target()

        redacted_title = redact_text(title)
        new_evidence = redact_text(f_data.evidence) if f_data.evidence else None
        new_description = redact_text(f_data.description) if f_data.description else None
        incoming_verified = bool(f_data.verified) if f_data.verified is not None else False
        incoming_fp = bool(f_data.is_false_positive) if f_data.is_false_positive is not None else False

        key = _dedup_key(redacted_title, finding_type, target, new_evidence)
        existing = existing_by_key.get(key)
        # If evidence was missing/placeholder previously, allow upgrade-in-place to avoid duplicates.
        if existing is None and _evidence_key(new_evidence):
            fallback_key = _dedup_key(redacted_title, finding_type, target, None)
            existing = existing_by_key.get(fallback_key)
            if existing is not None:
                existing_by_key.pop(fallback_key, None)
                existing_keys.discard(fallback_key)
                existing_by_key[key] = existing
                existing_keys.add(key)
        
        # 🎯 UPSERT: If title exists, update evidence/severity if they improved
        if existing is not None:
            if existing:
                needs_update = False
                # Upgrade severity (never downgrade)
                sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                old_sev_val = sev_order.get(existing.severity.value if hasattr(existing.severity, 'value') else str(existing.severity), 0)
                new_sev_val = sev_order.get(sev.value if hasattr(sev, 'value') else str(sev), 0)
                if new_sev_val > old_sev_val:
                    existing.severity = sev
                    needs_update = True
                # Update evidence if new evidence is longer/better
                if new_evidence and (not existing.evidence or len(new_evidence) > len(existing.evidence)):
                    existing.evidence = new_evidence
                    needs_update = True
                # Update description if changed
                if new_description and new_description != existing.description:
                    existing.description = new_description
                    needs_update = True
                # Upgrade verification/false-positive flags (never downgrade)
                if incoming_verified and not getattr(existing, "verified", False):
                    existing.verified = True
                    needs_update = True
                if incoming_fp and not getattr(existing, "is_false_positive", False):
                    existing.is_false_positive = True
                    needs_update = True
                if needs_update:
                    updated += 1
                else:
                    skipped += 1
            else:
                skipped += 1
            continue
        existing_keys.add(key)
        
        finding = Finding(
            job_id=job.id,
            tenant_id=tenant_id,
            title=redacted_title,
            description=new_description,
            severity=sev,
            finding_type=finding_type,
            cve_id=f_data.cve_id,
            cwe_id=f_data.cwe_id,
            mitre_technique=f_data.mitre_technique,
            target=target,
            evidence=new_evidence,
            proof_of_concept=redact_text(f_data.proof_of_concept) if f_data.proof_of_concept else None,
            remediation=redact_text(f_data.remediation) if f_data.remediation else None,
            verified=incoming_verified,
            is_false_positive=incoming_fp,
        )
        db.add(finding)
        existing_by_key[key] = finding
        created.append(str(finding.id))
    
    await db.commit()

    # Update job counts based on VERIFIED findings only (excluding marked false positives).
    count_result = await db.execute(
        select(Finding.severity).where(
            Finding.job_id == job.id,
            Finding.verified.is_(True),
            Finding.is_false_positive.is_(False),
        )
    )
    final_sevs = [row[0].value if hasattr(row[0], 'value') else str(row[0]) for row in count_result.fetchall()]
    job.findings_count = len(final_sevs)
    job.critical_count = final_sevs.count("critical")
    job.high_count = final_sevs.count("high")
    await db.commit()
    
    return {"created": len(created), "updated": updated, "skipped": skipped, "finding_ids": created}


@router.get("/{job_id}/findings")
async def get_findings(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all findings for a job"""
    from ..models import Finding
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")
    
    result = await db.execute(
        select(Finding).where(Finding.job_id == uuid.UUID(job_id))
    )
    findings = result.scalars().all()
    
    return [
        {
            "id": str(f.id),
            "title": redact_text(f.title),
            "description": redact_text(f.description) if f.description else None,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "finding_type": f.finding_type,
            "target": f.target,
            "evidence": redact_text(f.evidence) if f.evidence else None,
            "proof_of_concept": redact_text(f.proof_of_concept) if f.proof_of_concept else None,
            "verified": bool(getattr(f, "verified", False)),
            "is_false_positive": bool(getattr(f, "is_false_positive", False)),
            "mitre_technique": f.mitre_technique,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]


@router.get("/{job_id}/logs")
async def get_job_logs(
    job_id: str,
    log_type: str = Query("all", pattern="^(all|commands|llm)$"),
    limit: int = Query(200, ge=1, le=1000),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get detailed logs for a job"""
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    import os as _os
    import json as _json

    # Resolve log directory from transaction logger if available
    log_dir = None
    if request is not None:
        logger_obj = getattr(request.app.state, "transaction_logger", None)
        if logger_obj is not None:
            log_dir = getattr(logger_obj, "log_dir", None)
    if not log_dir:
        log_dir = _os.getenv("LOG_DIR", "/app/logs")

    files_by_type = {
        "commands": ["command_executions.jsonl"],
        "llm": ["llm_interactions.jsonl"],
        "all": ["job_events.jsonl", "command_executions.jsonl", "llm_interactions.jsonl"],
    }

    files = files_by_type.get(log_type, files_by_type["all"])
    entries = []
    for fname in files:
        path = _os.path.join(log_dir, fname)
        if not _os.path.exists(path):
            continue
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = _json.loads(line)
                    except Exception:
                        continue
                    if str(obj.get("job_id")) != str(job_id):
                        continue
                    obj["log_type"] = fname.replace(".jsonl", "")
                    entries.append(redact_obj(obj))
        except Exception:
            continue

    # Return most recent entries
    entries = entries[-limit:]

    return {
        "job_id": job_id,
        "log_type": log_type,
        "logs": entries,
        "count": len(entries),
    }


@router.get("/{job_id}/output")
async def get_job_output(
    job_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get buffered output lines for a job (polling fallback for WebSocket)"""
    import json as json_lib
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")
    
    redis_client = request.app.state.redis
    log_key = f"job:{job_id}:log"
    
    try:
        raw_lines = await redis_client.lrange(log_key, offset, offset + limit - 1)
        lines = []
        for raw in raw_lines:
            try:
                obj = json_lib.loads(raw)
                if isinstance(obj, dict) and "line" in obj:
                    obj["line"] = redact_text(str(obj.get("line", "")))
                lines.append(obj)
            except (json_lib.JSONDecodeError, TypeError):
                lines.append({"line": redact_text(str(raw))})
        
        total = await redis_client.llen(log_key)
        
        return {
            "job_id": job_id,
            "lines": lines,
            "offset": offset,
            "total": total
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "lines": [],
            "offset": offset,
            "total": 0,
            "error": str(e)
        }


@router.get("/{job_id}/live-intel")
async def get_job_live_intel(
    job_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get live intelligence data across ALL kill-chain phases.

    Reads ports, tech stack, web paths, exploit matches, vulnerability
    tracking, exploitation results, credentials, tools used, and recent
    agent activity from the job output directory.
    """
    import json as json_lib
    import re as re_mod
    from pathlib import Path

    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    output_dir = f"/pentest/output/{job_id}"
    empty_response = {
        "job_id": job_id,
        "error": "Job output directory not found",
        # RECON
        "ports": [], "tech_stack": {}, "web_paths": [],
        "exploits_matched": [],
        # SCANNING
        "vulnerabilities": [],
        # EXPLOITATION
        "exploitation_attempts": [],
        "access_level": None,
        # POST-EXPLOITATION
        "credentials_found": [], "arsenal": {},
        "cookies": [],
        # ALL PHASES
        "tools_used": [],
        "current_phase": None,
        "last_activity": None,
        "agent_log_tail": [],
        "findings": [],
        "raw_nmap": "",
    }

    if not os.path.isdir(output_dir):
        return empty_response

    ansi_escape = re_mod.compile(r'\x1b\[[0-9;]*[mK]')
    jwt_full_re = re_mod.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
    jwt_trunc_re = re_mod.compile(r'eyJ[a-zA-Z0-9_-]{20,}(?:\.[a-zA-Z0-9_-]{20,}){0,2}')
    bearer_re = re_mod.compile(r'(\bBearer\s+)[A-Za-z0-9._-]{10,}', re_mod.IGNORECASE)
    pw_json_re = re_mod.compile(r'(\"password\"\s*:\s*\")[^\"]+(\")', re_mod.IGNORECASE)
    pw_kv_re = re_mod.compile(r'(\b(?:password|pass|pwd)=)[^\\s&]+', re_mod.IGNORECASE)

    def _redact_sensitive(text: str) -> str:
        """Best-effort redaction for tokens/passwords before returning to UI."""
        if not text:
            return ""
        try:
            text = jwt_full_re.sub("<<JWT_REDACTED>>", text)
            text = jwt_trunc_re.sub("<<JWT_REDACTED>>", text)
            text = bearer_re.sub(r"\1<<BEARER_REDACTED>>", text)
            text = pw_json_re.sub(r"\1<<REDACTED>>\2", text)
            text = pw_kv_re.sub(r"\1<<REDACTED>>", text)
        except Exception:
            pass
        return text

    def _read_file(filepath: str) -> str:
        """Read a file, return '' on failure."""
        try:
            full = filepath if filepath.startswith("/") else os.path.join(output_dir, filepath)
            if os.path.isfile(full):
                with open(full, "r", errors="replace") as f:
                    return f.read()
        except Exception:
            pass
        return ""

    def _read_json(filepath: str):
        """Read and parse JSON file, return None on failure."""
        raw = _read_file(filepath)
        if raw:
            try:
                return json_lib.loads(raw)
            except Exception:
                pass
        return None

    # Best-effort: access.json is a more reliable source of access level than parsing
    # command strings (which may contain misleading tokens like PHP's system()).
    access_json = _read_json(f"{output_dir}/access.json")

    # =====================================================================
    # RECON PHASE: Ports, Tech Stack, Web Paths, Exploit Matches
    # =====================================================================

    # ── Ports (gnmap → nmap txt fallback) ──
    ports = []
    raw_nmap = ""

    # Prefer agent-written ports.json when present.
    ports_json = _read_json(f"{output_dir}/ports.json")
    if isinstance(ports_json, dict) and isinstance(ports_json.get("ports"), list):
        for p in ports_json.get("ports", []):
            if not isinstance(p, dict):
                continue
            try:
                port_num = int(p.get("port"))
            except Exception:
                continue
            ports.append(
                {
                    "port": port_num,
                    "protocol": str(p.get("protocol") or "tcp"),
                    "service": str(p.get("service") or p.get("name") or "unknown"),
                    "state": str(p.get("state") or "open"),
                }
            )
    gnmap = _read_file(f"{output_dir}/nmap_fast.gnmap") or _read_file(f"{output_dir}/nmap.gnmap")
    if gnmap:
        raw_nmap = gnmap[:500]
        for line in gnmap.split("\n"):
            if line.startswith("Host:") and "Ports:" in line:
                for port_entry in line.split("Ports:")[1].strip().split(","):
                    parts = port_entry.strip().split("/")
                    if len(parts) >= 5:
                        try:
                            if parts[1] == "open":
                                ports.append({"port": int(parts[0]), "protocol": parts[2],
                                              "service": parts[4] or "unknown", "state": "open"})
                        except (ValueError, IndexError):
                            pass
    if not ports:
        # Try multiple nmap output filenames (agents name these differently)
        nmap_txt = None
        for pattern in ["nmap_fast.nmap", "nmap.nmap", "nmap_fast.txt", "nmap.txt",
                         "nmap_initial.txt", "quick_scan.txt", "services_scan.txt",
                         "nmap_full.nmap", "nmap_full.txt", "nmap_svc.nmap"]:
            nmap_txt = _read_file(f"{output_dir}/{pattern}")
            if nmap_txt:
                break
        if nmap_txt:
            raw_nmap = raw_nmap or nmap_txt[:500]
            for m in re_mod.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', nmap_txt):
                ports.append({"port": int(m.group(1)), "protocol": m.group(2),
                              "service": m.group(3), "state": "open"})
    # Deduplicate
    seen_ports = set()
    unique_ports = []
    for p in ports:
        key = (p["port"], p["protocol"])
        if key not in seen_ports:
            seen_ports.add(key)
            unique_ports.append(p)
    ports = sorted(unique_ports, key=lambda x: x["port"])

    # ── Tech fingerprint (WhatWeb JSON or plain dict) ──
    tech_stack = {}
    parsed = _read_json(f"{output_dir}/tech_fingerprint.json")
    if isinstance(parsed, dict):
        tech_stack = parsed
    elif isinstance(parsed, list) and parsed:
        entry = parsed[0] if isinstance(parsed[0], dict) else {}
        for pname, pdata in entry.get("plugins", {}).items():
            if isinstance(pdata, dict):
                version = pdata.get("version", [])
                string_val = pdata.get("string", [])
                if version:
                    tech_stack[pname] = version[0] if isinstance(version, list) else str(version)
                elif string_val:
                    tech_stack[pname] = string_val[0] if isinstance(string_val, list) else str(string_val)
                elif pdata:
                    tech_stack[pname] = "detected"

    # ── Web paths (gobuster / ffuf) ──
    web_paths = []
    seen_paths = set()
    gobuster_raw = None
    for gname in ["gobuster.txt", "gobuster_results.txt", "dir_enum.txt", "ffuf_paths.json"]:
        gobuster_raw = _read_file(f"{output_dir}/{gname}")
        if gobuster_raw:
            break
    if gobuster_raw:
        for line in gobuster_raw.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("=") or line.startswith("Gobuster"):
                continue
            m = re_mod.match(r'(/?\S+)\s+\(Status:\s*(\d+)\)', line) or \
                re_mod.match(r'(\S+)\s+.*\(Status:\s*(\d+)\)', line) or \
                re_mod.match(r'(/?\S+)\s+\[Status:\s*(\d+)', line)
            if m:
                path = "/" + m.group(1).lstrip("/")
                if path.lower() not in seen_paths:
                    seen_paths.add(path.lower())
                    web_paths.append({"path": path, "status": int(m.group(2))})

    # ── Exploit DB matches ──
    exploits_matched = []
    seen_exploits = set()
    # Try multiple exploitdb filenames (agents save these differently)
    exploitdb_raw = None
    for epath in [f"{output_dir}/evidence/exploitdb.txt", f"{output_dir}/exploitdb.txt"]:
        exploitdb_raw = _read_file(epath)
        if exploitdb_raw:
            break
    if not exploitdb_raw:
        # Glob for exploitdb*.json or exploitdb*.txt in output_dir
        import glob
        for pattern in [f"{output_dir}/exploitdb*.json", f"{output_dir}/exploitdb*.txt",
                        f"{output_dir}/evidence/exploitdb*.json", f"{output_dir}/evidence/exploitdb*.txt"]:
            for fpath in glob.glob(pattern):
                exploitdb_raw = _read_file(fpath)
                if exploitdb_raw:
                    break
            if exploitdb_raw:
                break
    if exploitdb_raw:
        # Some wrappers/scripts print extra preamble (HTML, cookies, etc.) around the
        # actual searchsploit output. If a SEARCHSPLOIT marker is present, keep only
        # the section after the last marker to avoid polluting the UI.
        try:
            markers = list(re_mod.finditer(r"^---\s*searchsploit\s*---\s*$", exploitdb_raw, flags=re_mod.I | re_mod.M))
            if markers:
                exploitdb_raw = exploitdb_raw[markers[-1].end():]
        except Exception:
            pass

        exploitdb_raw_clean = exploitdb_raw.strip()
        parsed_json = False

        # Try parsing as JSON first (searchsploit -j output)
        if exploitdb_raw_clean.startswith("{"):
            try:
                # Fix common JSON issues: trailing commas, truncated arrays
                fixed = exploitdb_raw_clean.rstrip()
                if fixed.endswith(","):
                    fixed = fixed[:-1]
                # Close unclosed arrays/objects
                open_brackets = fixed.count("[") - fixed.count("]")
                open_braces = fixed.count("{") - fixed.count("}")
                fixed += "]" * open_brackets + "}" * open_braces
                obj = json_lib.loads(fixed)
                results = obj.get("RESULTS_EXPLOIT", [])
                if isinstance(results, list):
                    for item in results:
                        if not isinstance(item, dict):
                            continue
                        title = item.get("Title", "").strip()
                        if not title:
                            continue
                        path = item.get("Path", "").strip()
                        edb_id = item.get("EDB-ID", "")
                        platform = item.get("Platform", "")
                        exploit_type = item.get("Type", "")
                        # Build clean display: Title — filename (EDB-ID) [platform/type]
                        display = title
                        if path:
                            filename = path.rsplit("/", 1)[-1] if "/" in path else path
                            display += f" — {filename}"
                        tags = []
                        if edb_id:
                            tags.append(f"EDB-{edb_id}")
                        if platform:
                            tags.append(platform)
                        if exploit_type:
                            tags.append(exploit_type)
                        if tags:
                            display += f" [{', '.join(tags)}]"
                        if display not in seen_exploits:
                            seen_exploits.add(display)
                            exploits_matched.append(display)
                    parsed_json = True
            except (json_lib.JSONDecodeError, TypeError):
                pass

        # Fallback: parse line-by-line (table format or mixed)
        if not parsed_json:
            for line in exploitdb_raw.split("\n"):
                line = ansi_escape.sub('', line).strip()
                if not line or len(line) < 10:
                    continue
                if line.startswith("-") or line.startswith("Shellcodes") or line.startswith("Papers"):
                    continue
                if "Exploit Title" in line or "----" in line or line.startswith("[!]") or line.startswith("[*]"):
                    continue
                if line.startswith("--- searchsploit") or line.startswith("Exploits: No"):
                    continue
                # Table format: "Title | path"
                if "|" in line:
                    parts = line.split("|", 1)
                    title = parts[0].strip()
                    path = parts[1].strip() if len(parts) > 1 else ""
                    display = f"{title}"
                    if path:
                        display += f" — {path}"
                    if display not in seen_exploits:
                        seen_exploits.add(display)
                        exploits_matched.append(display)
    exploits_matched = exploits_matched[:30]

    # =====================================================================
    # SCANNING PHASE: Vulnerability Tracker
    # =====================================================================
    vulnerabilities = []
    vuln_tracker = _read_json(f"{output_dir}/vuln_tracker.json")
    if isinstance(vuln_tracker, dict):
        for vid, vdata in vuln_tracker.items():
            if not isinstance(vdata, dict):
                continue
            vulnerabilities.append({
                "id": vid,
                "type": vdata.get("type", "unknown"),
                "target": vdata.get("target", ""),
                "iteration_found": vdata.get("iteration_found"),
                "exploited": vdata.get("exploited", False),
                "attempted": vdata.get("attempted", False),
                "attempt_count": vdata.get("attempt_count", 0),
                "proof": _redact_sensitive((vdata.get("proof") or "")[:200]),
                "not_exploitable_reason": _redact_sensitive(vdata.get("not_exploitable_reason", "") or "")[:300],
            })

    # =====================================================================
    # EXPLOITATION PHASE: Attempts, Shells, Access Level
    # =====================================================================
    exploitation_attempts = []
    access_level = None

    # Prefer access.json for access level (avoids false positives from command text).
    if isinstance(access_json, dict):
        lvl = access_json.get("access_level")
        if isinstance(lvl, str) and lvl.strip():
            access_level = lvl.strip()
        else:
            uid = None
            if isinstance(access_json.get("webshell"), dict):
                uid = access_json["webshell"].get("uid")
            if uid is None and isinstance(access_json.get("shell"), dict):
                uid = access_json["shell"].get("uid")
            try:
                if isinstance(uid, str) and uid.strip().isdigit():
                    uid = int(uid.strip())
                if isinstance(uid, int):
                    access_level = "root" if uid == 0 else "user"
            except Exception:
                pass

    # Build exploitation timeline from vuln_tracker attempts
    if isinstance(vuln_tracker, dict):
        for vid, vdata in vuln_tracker.items():
            if not isinstance(vdata, dict):
                continue
            for attempt in (vdata.get("attempts") or [])[:5]:
                exploitation_attempts.append({
                    "vuln_id": vid,
                    "iteration": attempt.get("iteration"),
                    "command": _redact_sensitive((attempt.get("command") or "")[:200]),
                    "success": attempt.get("success", False),
                    "technique": attempt.get("technique", ""),
                    "evidence_snippet": _redact_sensitive((attempt.get("evidence") or "")[:150]),
                })
    exploitation_attempts.sort(key=lambda x: x.get("iteration") or 0)
    exploitation_attempts = exploitation_attempts[:50]

    # Determine access level from handoff.json or exploitation evidence
    handoff = _read_json(f"{output_dir}/handoff.json")
    if isinstance(handoff, dict):
        sessions = handoff.get("sessions", [])
        for s in sessions:
            cmd_lower = (s.get("command") or "").lower()
            # Avoid false positives like PHP's system() function; require explicit privilege markers.
            if "nt authority\\system" in cmd_lower or "nt authority/system" in cmd_lower:
                access_level = "SYSTEM"
            elif re_mod.search(r"\\buid=0\\b", cmd_lower) or "root:x:0:0" in cmd_lower:
                access_level = "root"
            elif "administrator" in cmd_lower and not access_level:
                access_level = "admin"
            elif not access_level:
                access_level = "user"

    # Also check from exploitation evidence
    if not access_level and any(a.get("success") for a in exploitation_attempts):
        access_level = "user"  # At minimum user-level if any exploit succeeded

    # Final fallback: infer from evidence snippets (these often contain outputs like uid=...).
    if not access_level:
        for a in exploitation_attempts:
            ev = (a.get("evidence_snippet") or "").lower()
            if "nt authority\\system" in ev or "nt authority/system" in ev:
                access_level = "SYSTEM"
                break
            if re_mod.search(r"\\buid=0\\b", ev) or "root:x:0:0" in ev:
                access_level = "root"
                break
            if "uid=" in ev or "www-data" in ev:
                access_level = "user"
                break

    # =====================================================================
    # POST-EXPLOITATION: Credentials, Arsenal, Cookies
    # =====================================================================
    credentials_found = []
    arsenal_data = {}
    arsenal = _read_json(f"{output_dir}/arsenal.json")
    if isinstance(arsenal, dict):
        for cred in arsenal.get("credentials", [])[:20]:
            credentials_found.append({
                "value": cred.get("value", ""),
                "source": cred.get("source", cred.get("source_command", ""))[:100],
                "iteration": cred.get("source_iteration"),
                "vuln": cred.get("source_vuln", ""),
            })
        # Expose full arsenal summary (counts per category)
        for cat, items in arsenal.items():
            if isinstance(items, list):
                arsenal_data[cat] = len(items)

    if not credentials_found:
        creds = _read_json(f"{output_dir}/evidence/credentials.json") or _read_json(f"{output_dir}/creds.json")
        if isinstance(creds, list):
            for c in creds[:20]:
                credentials_found.append({
                    "value": c.get("username", "") + ":" + c.get("password", ""),
                    "source": c.get("service", c.get("source", "")),
                    "iteration": c.get("iteration"),
                    "vuln": "",
                })

    cookies = []
    cookies_raw = _read_file(f"{output_dir}/cookies.txt")
    if cookies_raw:
        for line in cookies_raw.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                cookies.append(line[:200])
    cookies = cookies[:20]

    # =====================================================================
    # ALL PHASES: Tools, Findings, Agent Activity, Phase Detection
    # =====================================================================

    # ── Tools used ──
    tools_used = []
    exec_jsonl = _read_file(f"{output_dir}/agent_executions.jsonl")
    last_exec_entry = None
    if exec_jsonl:
        tool_stats = {}
        for line in exec_jsonl.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json_lib.loads(line)
                tool = entry.get("tool_used") or entry.get("tool") or "unknown"
                success = entry.get("success", False)
                if tool not in tool_stats:
                    tool_stats[tool] = {"success": 0, "fail": 0}
                if success:
                    tool_stats[tool]["success"] += 1
                else:
                    tool_stats[tool]["fail"] += 1
                last_exec_entry = entry
            except Exception:
                continue
        tools_used = [
            {"tool": t, "success": s["success"] > 0, "runs": s["success"] + s["fail"], "successes": s["success"]}
            for t, s in sorted(tool_stats.items())
        ]

    # ── Findings (from evidence/findings.json or findings.json) ──
    findings = []
    found_data = _read_json(f"{output_dir}/evidence/findings.json") or _read_json(f"{output_dir}/findings.json")
    if isinstance(found_data, list):
        for f in found_data[:30]:
            if isinstance(f, dict):
                findings.append({
                    "title": (f.get("title") or f.get("name") or "")[:150],
                    "severity": f.get("severity", "info"),
                    "type": f.get("finding_type") or f.get("type", ""),
                    "target": f.get("target") or f.get("location", ""),
                    "description": (f.get("description") or "")[:200],
                })

    # ── Agent log tail (last 15 meaningful lines) ──
    agent_log_tail = []
    agent_log = _read_file(f"{output_dir}/dynamic_agent.log")
    if agent_log:
        lines = agent_log.strip().split("\n")
        # Take last 50 lines, filter to meaningful ones, keep last 15
        meaningful = []
        for line in lines[-50:]:
            stripped = line.strip()
            if not stripped:
                continue
            # Skip very verbose/boring lines
            if any(skip in stripped for skip in ["Context chars trimmed", "AI response:"]):
                continue
            meaningful.append(stripped[:200])
        agent_log_tail = meaningful[-15:]

    # ── Current phase detection ──
    current_phase = None
    if agent_log_tail:
        last_lines = " ".join(agent_log_tail[-5:]).lower()
        if "exploit" in last_lines or "msfconsole" in last_lines or "shell" in last_lines:
            current_phase = "EXPLOITATION"
        elif "privesc" in last_lines or "post-exploit" in last_lines or "lateral" in last_lines:
            current_phase = "POST_EXPLOITATION"
        elif "gobuster" in last_lines or "nikto" in last_lines or "vuln" in last_lines or "scan" in last_lines:
            current_phase = "SCANNING"
        elif "nmap" in last_lines or "whatweb" in last_lines or "recon" in last_lines:
            current_phase = "RECON"
        else:
            current_phase = "ACTIVE"

    # ── Last activity ──
    last_activity = None
    if last_exec_entry:
        last_activity = {
            "command": _redact_sensitive((last_exec_entry.get("content") or "")[:200]),
            "tool": last_exec_entry.get("tool_used", ""),
            "success": last_exec_entry.get("success", False),
            "iteration": last_exec_entry.get("iteration"),
            "timestamp": last_exec_entry.get("timestamp", ""),
            "stdout_snippet": _redact_sensitive((last_exec_entry.get("stdout") or "")[:300]),
        }

    return {
        "job_id": job_id,
        # RECON
        "ports": ports,
        "tech_stack": tech_stack,
        "web_paths": web_paths[:50],
        "exploits_matched": exploits_matched,
        "raw_nmap": raw_nmap,
        # SCANNING
        "vulnerabilities": vulnerabilities,
        # EXPLOITATION
        "exploitation_attempts": exploitation_attempts,
        "access_level": access_level,
        # POST-EXPLOITATION
        "credentials_found": credentials_found,
        "arsenal": arsenal_data,
        "cookies": cookies,
        # ALL PHASES
        "tools_used": tools_used,
        "current_phase": current_phase,
        "last_activity": last_activity,
        "agent_log_tail": agent_log_tail,
        "findings": findings,
    }


@router.get("/{job_id}/live-stats")
async def get_job_live_stats(
    job_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get live stats for a running job (findings discovered so far, iteration count)"""
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")
    
    redis_client = request.app.state.redis
    stats_key = f"job:{job_id}:live_stats"
    
    try:
        stats = await redis_client.hgetall(stats_key)
        total_findings = int(stats.get("total_findings", 0))
        findings_this_run = int(stats.get("findings_this_run", 0))

        # ------------------------------------------------------------------
        # Augment/repair with persisted artifacts (volume-mounted from Kali).
        # ------------------------------------------------------------------
        # Repair/augment live stats from persisted artifacts.
        # This avoids undercounting when the agent doesn't emit [REMEMBER:] tags.
        output_dir = f"/pentest/output/{job_id}"
        try:
            total_findings = max(total_findings, int(getattr(job, "findings_count", 0) or 0))
        except Exception:
            pass
        # Prefer DB count for total findings (authoritative and includes resumes).
        try:
            res = await db.execute(
                select(func.count(Finding.id)).where(
                    and_(Finding.job_id == job.id, Finding.tenant_id == job.tenant_id)
                )
            )
            total_findings = max(total_findings, int(res.scalar() or 0))
        except Exception:
            pass

        # Vuln tracker (found + exploited breakdown)
        vulns_exploited = 0
        vulns_total = int(stats.get("vulnerabilities", 0) or 0)
        try:
            import json as _json
            vt_path = os.path.join(output_dir, "vuln_tracker.json")
            if os.path.exists(vt_path):
                with open(vt_path, "r") as f:
                    vt = _json.load(f)
                if isinstance(vt, dict):
                    vulns_total = max(vulns_total, len(vt))
                    try:
                        vulns_exploited = sum(
                            1
                            for _v in vt.values()
                            if isinstance(_v, dict) and bool(_v.get("exploited") or _v.get("proof"))
                        )
                    except Exception:
                        vulns_exploited = 0
                    stats["vulnerabilities"] = str(vulns_total)
        except Exception:
            pass
        vulns_unexploited = max(0, int(vulns_total or 0) - int(vulns_exploited or 0))

        try:
            import json as _json
            arsenal_path = os.path.join(output_dir, "arsenal.json")
            if os.path.exists(arsenal_path):
                with open(arsenal_path, "r") as f:
                    arsenal = _json.load(f)
                if isinstance(arsenal, dict) and isinstance(arsenal.get("credentials"), list):
                    stats["credentials"] = str(
                        max(int(stats.get("credentials", 0) or 0), len([c for c in arsenal["credentials"] if isinstance(c, dict)]))
                    )
        except Exception:
            pass

        try:
            access_path = os.path.join(output_dir, "access.json")
            if os.path.exists(access_path) and os.path.getsize(access_path) > 10:
                stats["access_gained"] = str(max(int(stats.get("access_gained", 0) or 0), 1))
        except Exception:
            pass

        # Last activity + stall detection
        last_activity = None
        stall_seconds = None
        stalled = False
        try:
            import json as _json
            from datetime import datetime, timezone

            # Prefer Redis buffered logs if present (accurate for running jobs).
            last_line = await redis_client.lindex(f"job:{job_id}:log", -1)
            if last_line:
                try:
                    obj = _json.loads(last_line)
                    if isinstance(obj, dict) and obj.get("timestamp"):
                        last_activity = str(obj["timestamp"])
                except Exception:
                    last_activity = None

            # Fall back to file mtimes (works for completed jobs or if Redis is missing data).
            if not last_activity:
                candidates = [
                    os.path.join(output_dir, "dynamic_agent.log"),
                    os.path.join(output_dir, "agent_executions.jsonl"),
                    os.path.join(output_dir, "llm_interactions.jsonl"),
                ]
                newest_mtime = None
                for p in candidates:
                    try:
                        if os.path.exists(p):
                            mt = os.path.getmtime(p)
                            newest_mtime = mt if newest_mtime is None else max(newest_mtime, mt)
                    except Exception:
                        pass
                if newest_mtime:
                    last_activity = datetime.fromtimestamp(newest_mtime, tz=timezone.utc).isoformat()

            if last_activity:
                try:
                    # Handle both Z and offset ISO formats
                    ts = last_activity.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(ts)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    stall_seconds = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
                except Exception:
                    stall_seconds = None

            # Stall if job claims running but hasn't produced output for a while.
            try:
                status_val = getattr(job, "status", None)
                status_str = status_val.value if hasattr(status_val, "value") else str(status_val or "")
                # Flag stalls only once a job is actually in-flight (running/queued).
                if status_str in ("running", "queued") and stall_seconds is not None and stall_seconds >= 300:
                    stalled = True
            except Exception:
                pass
        except Exception:
            pass

        # Progress-based stall detection: use the timestamp of the most recent
        # iteration line to detect "alive but not making progress" cases.
        last_progress_activity = None
        last_progress_iteration = None
        progress_stall_seconds = None
        progress_stalled = False
        try:
            import json as _json
            import re as _re
            from datetime import datetime, timezone

            it_re = _re.compile(r"=== Iteration (\d+)/(\d+) ===")

            # Prefer Redis job logs (cheap); scan a small window from the tail.
            try:
                recent = await redis_client.lrange(f"job:{job_id}:log", -400, -1)
            except Exception:
                recent = []
            if recent:
                for entry in reversed(recent):
                    try:
                        obj = _json.loads(entry)
                        if not isinstance(obj, dict):
                            continue
                        line = obj.get("line")
                        if not isinstance(line, str):
                            continue
                        m = it_re.search(line)
                        if not m:
                            continue
                        last_progress_iteration = int(m.group(1))
                        ts = obj.get("timestamp")
                        if isinstance(ts, str) and ts:
                            last_progress_activity = ts
                        break
                    except Exception:
                        continue

            # Fall back to parsing the agent log file if Redis is missing iteration lines.
            if not last_progress_activity:
                dyn_path = os.path.join(output_dir, "dynamic_agent.log")
                if os.path.exists(dyn_path):
                    with open(dyn_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()[-4000:]
                    ts_it_re = _re.compile(r"^\[(?P<ts>[^\]]+)\].*=== Iteration (?P<it>\d+)/(\d+) ===")
                    for ln in reversed(lines):
                        m = ts_it_re.search(ln)
                        if m:
                            last_progress_iteration = int(m.group("it"))
                            last_progress_activity = m.group("ts")
                            break

            if last_progress_activity:
                try:
                    ts = last_progress_activity.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(ts)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    progress_stall_seconds = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
                except Exception:
                    progress_stall_seconds = None

            try:
                status_val = getattr(job, "status", None)
                status_str = status_val.value if hasattr(status_val, "value") else str(status_val or "")
                # Use a higher threshold than log-based stall to avoid flagging slow LLM calls.
                if status_str in ("running", "queued") and progress_stall_seconds is not None and progress_stall_seconds >= 900:
                    progress_stalled = True
            except Exception:
                pass

            stalled = bool(stalled or progress_stalled)
        except Exception:
            pass

        # Loop detection (lightweight): repeated iteration numbers in recent dynamic_agent.log.
        loop_detected = False
        loop_max_consecutive_same_iteration = 0
        loop_repeated_iterations = 0
        try:
            import re as _re
            dyn_path = os.path.join(output_dir, "dynamic_agent.log")
            if os.path.exists(dyn_path):
                # File is typically small (< 100KB). Read fully and analyze last ~2000 lines.
                with open(dyn_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()[-2000:]
                it_re = _re.compile(r"=== Iteration (\d+)/(\d+) ===")
                its = []
                for ln in lines:
                    m = it_re.search(ln)
                    if m:
                        its.append(int(m.group(1)))
                if its:
                    # consecutive repeats
                    last = None
                    cur = 0
                    max_consec = 0
                    for it in its:
                        if it == last:
                            cur += 1
                        else:
                            cur = 1
                        max_consec = max(max_consec, cur)
                        last = it
                    loop_max_consecutive_same_iteration = int(max_consec)
                    # non-consecutive repeats
                    from collections import Counter
                    c = Counter(its)
                    loop_repeated_iterations = sum(1 for v in c.values() if v > 1)
                    # Avoid noisy alerts: only flag as a loop when repetition is sustained.
                    loop_detected = loop_max_consecutive_same_iteration >= 5 or loop_repeated_iterations >= 10
        except Exception:
            pass

        return {
            "job_id": job_id,
            "status": getattr(job, "status", None).value if getattr(job, "status", None) else None,
            "current_iteration": int(stats.get("current_iteration", 0)),
            "max_iterations": int(stats.get("max_iterations", 0)),
            "total_findings": total_findings,
            "findings_this_run": findings_this_run,
            "findings_inherited": max(0, total_findings - findings_this_run),
            "credentials": int(stats.get("credentials", 0)),
            "vulnerabilities": int(stats.get("vulnerabilities", 0)),
            "vulns_exploited": int(vulns_exploited or 0),
            "vulns_unexploited": int(vulns_unexploited or 0),
            "access_gained": int(stats.get("access_gained", 0)),
            "tokens_used": int(stats.get("tokens_used", 0)),
            "cost_usd": stats.get("cost_usd", "0"),
            "critical_count": int(getattr(job, "critical_count", 0) or 0),
            "high_count": int(getattr(job, "high_count", 0) or 0),
            "last_activity": last_activity,
            "stall_seconds": stall_seconds,
            "stalled": stalled,
            "last_progress_activity": last_progress_activity,
            "last_progress_iteration": last_progress_iteration,
            "progress_stall_seconds": progress_stall_seconds,
            "progress_stalled": progress_stalled,
            "loop_detected": loop_detected,
            "loop_max_consecutive_same_iteration": loop_max_consecutive_same_iteration,
            "loop_repeated_iterations": loop_repeated_iterations,
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "current_iteration": 0,
            "max_iterations": 0,
            "total_findings": 0,
            "findings_this_run": 0,
            "findings_inherited": 0,
            "credentials": 0,
            "vulnerabilities": 0,
            "access_gained": 0,
        }


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _target_in_scope(target: str, allowed: list, excluded: list) -> bool:
    """Check if target is within scope.

    Supports:
      - exact matches (host, IP, CIDR, URL)
      - domain suffix matches (e.g. ".example.com" or "example.com")
      - CIDR containment for IP targets (IPv4/IPv6)
      - host:port exact matches
    """
    import ipaddress
    from urllib.parse import urlparse

    def _parse(value: str) -> dict:
        s = (value or "").strip()
        if not s:
            return {"raw": ""}

        # URL form
        if "://" in s:
            try:
                u = urlparse(s)
                if u.hostname:
                    host = u.hostname.strip("[]")
                    port = u.port
                    ip = None
                    try:
                        ip = ipaddress.ip_address(host)
                    except Exception:
                        ip = None
                    return {"raw": s, "host": host, "port": port, "ip": ip, "net": None}
            except Exception:
                pass

        # CIDR form (treat as a "network target")
        try:
            net = ipaddress.ip_network(s, strict=False)
            return {"raw": s, "host": None, "port": None, "ip": None, "net": net}
        except Exception:
            net = None

        # Strip any path/query fragments (but keep CIDR above)
        base = s.split("/", 1)[0]

        host = base
        port = None
        # host:port (ignore IPv6 here; it should be URL form or raw IP)
        if ":" in base and base.count(":") == 1:
            h, p = base.rsplit(":", 1)
            if p.isdigit():
                host = h
                try:
                    port = int(p)
                except Exception:
                    port = None

        host = host.strip("[]")
        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except Exception:
            ip = None
        return {"raw": s, "host": host, "port": port, "ip": ip, "net": net}

    def _matches(t: dict, rule: dict) -> bool:
        # Exact raw match always counts.
        if rule.get("raw") and t.get("raw") and t["raw"] == rule["raw"]:
            return True

        # CIDR rule
        if rule.get("net") is not None:
            if t.get("ip") is not None:
                return t["ip"] in rule["net"]
            if t.get("net") is not None:
                # allow a subnet if fully contained
                return t["net"].subnet_of(rule["net"])
            return False

        # Host rule (optionally with port)
        rule_host = rule.get("host")
        if not rule_host:
            return False

        t_host = t.get("host") or ""
        if not t_host:
            return False

        # If rule specifies a port, require the target to specify the same port.
        rule_port = rule.get("port")
        if rule_port is not None:
            return t_host == rule_host and t.get("port") == rule_port

        # Exact host match or suffix match
        return t_host == rule_host or t_host.endswith(rule_host)

    tinfo = _parse(target)
    if not tinfo.get("raw"):
        return False

    excluded_rules = [_parse(x) for x in (excluded or []) if x]
    allowed_rules = [_parse(x) for x in (allowed or []) if x]

    for r in excluded_rules:
        if _matches(tinfo, r):
            return False

    return any(_matches(tinfo, r) for r in allowed_rules)

def _job_to_response(job: Job) -> JobResponse:
    """Convert Job model to response"""
    return JobResponse(
        id=str(job.id),
        name=job.name,
        description=job.description,
        scope_id=str(job.scope_id) if job.scope_id else None,
        phase=job.phase,
        targets=job.targets,
        target_type=job.target_type or "lab",
        intensity=getattr(job, 'intensity', None),
        timeout_seconds=getattr(job, 'timeout_seconds', None),
        max_iterations=getattr(job, 'max_iterations', 30) or 30,
        authorization_confirmed=getattr(job, 'authorization_confirmed', False) or False,
        exploit_mode=getattr(job, 'exploit_mode', 'explicit_only') or "explicit_only",
        llm_provider=getattr(job, 'llm_provider', None),
        llm_profile=getattr(job, 'llm_profile', None),
        agent_freedom=getattr(job, 'agent_freedom', None),
        supervisor_enabled=getattr(job, 'supervisor_enabled', None),
        supervisor_provider=getattr(job, 'supervisor_provider', None),
        allow_persistence=bool(getattr(job, 'allow_persistence', False)),
        allow_defense_evasion=bool(getattr(job, 'allow_defense_evasion', False)),
        allow_scope_expansion=bool(getattr(job, 'allow_scope_expansion', False)),
        enable_session_handoff=bool(getattr(job, 'enable_session_handoff', False)),
        enable_target_rotation=bool(getattr(job, 'enable_target_rotation', True)),
        target_focus_window=int(getattr(job, 'target_focus_window', 6) or 6),
        target_focus_limit=int(getattr(job, 'target_focus_limit', 30) or 30),
        target_min_commands=int(getattr(job, 'target_min_commands', 8) or 8),
        status=job.status.value if hasattr(job.status, 'value') else str(job.status),
        progress=job.progress,
        findings_count=job.findings_count,
        critical_count=job.critical_count,
        high_count=job.high_count,
        tokens_used=job.tokens_used,
        cost_usd=job.cost_usd / 100,  # Convert from cents
        worker_id=getattr(job, "worker_id", None),
        container_id=getattr(job, "container_id", None),
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        result=redact_obj(job.result) if job.result else None
    )
