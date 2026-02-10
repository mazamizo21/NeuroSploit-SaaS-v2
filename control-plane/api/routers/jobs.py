"""
TazoSploit SaaS v2 - Jobs Router
Job creation, management, and execution control
"""

import os
import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import structlog

from ..database import get_db
from ..utils.redact import redact_obj, redact_text
from ..models import Job, JobStatus, Scope, Tenant, AuditLog
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

    llm_provider_override = (job_data.llm_provider or "").strip().lower()
    supervisor_provider_override = (job_data.supervisor_provider or "").strip().lower()
    if llm_provider_override or supervisor_provider_override:
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
        job.cost_usd = update.cost_usd
    if update.error_message is not None:
        job.error_message = redact_text(update.error_message)

    # Process result data from worker
    if update.result:
        # Redact secrets defensively before persisting
        safe_result = redact_obj(update.result)

        # Store the full result JSON
        job.result = safe_result
        
        findings = safe_result.get("findings", [])
        if findings:
            job.findings_count = len(findings)
            job.critical_count = sum(1 for f in findings if f.get("severity") == "critical")
            job.high_count = sum(1 for f in findings if f.get("severity") == "high")
        
        # Also check comprehensive_findings for counts
        comp = safe_result.get("comprehensive_findings", {})
        summary = comp.get("summary", {})
        if summary:
            cred_count = summary.get("credentials", 0)
            vuln_count = summary.get("vulnerabilities", 0)
            db_count = summary.get("database_access", 0)
            shell_count = summary.get("shell_access", 0)
            total = cred_count + vuln_count + db_count + shell_count
            if total > job.findings_count:
                job.findings_count = total
                # Estimate severity from vulns
                job.critical_count = max(job.critical_count, shell_count)
                job.high_count = max(job.high_count, vuln_count)
        
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
    existing_by_title = {f.title: f for f in existing_result.scalars().all()}
    existing_titles = set(existing_by_title.keys())
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
        
        # 🎯 UPSERT: If title exists, update evidence/severity if they improved
        if redacted_title in existing_titles:
            existing = existing_by_title.get(redacted_title)
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
                if needs_update:
                    updated += 1
                else:
                    skipped += 1
            else:
                skipped += 1
            continue
        existing_titles.add(redacted_title)
        
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
        )
        db.add(finding)
        existing_by_title[redacted_title] = finding
        created.append(str(finding.id))
    
    # 🐛 FIX: Update job counts CUMULATIVELY (total in DB, not just this batch)
    total_result = await db.execute(
        select(Finding.severity).where(Finding.job_id == job.id)
    )
    all_severities = [row[0].value if hasattr(row[0], 'value') else row[0] for row in total_result.fetchall()]
    # Add the ones we're about to commit
    for fid in created:
        pass  # already counted in all_severities after flush
    job.findings_count = len(existing_titles)  # total unique findings
    job.critical_count = all_severities.count("critical") + sum(1 for f in findings if f.severity == "critical" and redact_text(f.get_title()) in {redact_text(f2.get_title()) for f2 in findings[:len(created)]})
    job.high_count = all_severities.count("high") + sum(1 for f in findings if f.severity == "high" and redact_text(f.get_title()) in {redact_text(f2.get_title()) for f2 in findings[:len(created)]})
    
    await db.commit()
    
    # 🔄 Re-count properly after commit
    count_result = await db.execute(
        select(Finding.severity).where(Finding.job_id == job.id)
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
        return {
            "job_id": job_id,
            "current_iteration": int(stats.get("current_iteration", 0)),
            "max_iterations": int(stats.get("max_iterations", 0)),
            "total_findings": total_findings,
            "findings_this_run": findings_this_run,
            "findings_inherited": max(0, total_findings - findings_this_run),
            "credentials": int(stats.get("credentials", 0)),
            "vulnerabilities": int(stats.get("vulnerabilities", 0)),
            "access_gained": int(stats.get("access_gained", 0)),
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
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        result=redact_obj(job.result) if job.result else None
    )
