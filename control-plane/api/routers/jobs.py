"""
NeuroSploit SaaS v2 - Jobs Router
Job creation, management, and execution control
"""

import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import structlog

from ..database import get_db
from ..models import Job, JobStatus, Scope, Tenant, AuditLog
from ..auth import get_current_user, require_permission

logger = structlog.get_logger()
router = APIRouter()

# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class JobCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scope_id: str
    phase: str = Field(..., pattern="^(RECON|VULN_SCAN|EXPLOIT|POST_EXPLOIT|REPORT)$")
    targets: List[str]
    intensity: str = Field(default="medium", pattern="^(low|medium|high)$")
    timeout_seconds: int = Field(default=3600, ge=60, le=14400)
    auto_run: bool = False

class JobResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    scope_id: Optional[str]
    phase: str
    targets: List[str]
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
    
    logger.info(
        "job_create_started",
        tenant_id=str(tenant_id),
        phase=job_data.phase,
        targets=job_data.targets
    )
    
    # Verify scope exists and belongs to tenant
    scope = await db.get(Scope, uuid.UUID(job_data.scope_id))
    if not scope or scope.tenant_id != tenant_id:
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
    if intensity_order.get(job_data.intensity, 0) > intensity_order.get(scope.max_intensity, 2):
        raise HTTPException(
            status_code=400,
            detail=f"Intensity '{job_data.intensity}' exceeds scope limit '{scope.max_intensity}'"
        )
    
    # Check tenant quotas
    tenant = await db.get(Tenant, tenant_id)
    running_jobs = await db.execute(
        select(Job).where(
            and_(
                Job.tenant_id == tenant_id,
                Job.status.in_([JobStatus.PENDING, JobStatus.QUEUED, JobStatus.RUNNING])
            )
        )
    )
    if len(running_jobs.scalars().all()) >= tenant.max_concurrent_jobs:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum concurrent jobs ({tenant.max_concurrent_jobs}) reached"
        )
    
    # Create job
    job = Job(
        tenant_id=tenant_id,
        scope_id=scope.id,
        created_by=current_user.id,
        name=job_data.name,
        description=job_data.description,
        phase=job_data.phase,
        targets=job_data.targets,
        intensity=job_data.intensity,
        timeout_seconds=job_data.timeout_seconds,
        auto_run=job_data.auto_run,
        status=JobStatus.PENDING
    )
    
    db.add(job)
    await db.flush()
    
    # Audit log
    audit = AuditLog(
        tenant_id=tenant_id,
        user_id=current_user.id,
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
    
    query = select(Job).where(Job.tenant_id == tenant_id)
    
    if status:
        query = query.where(Job.status == status)
    if phase:
        query = query.where(Job.phase == phase)
    
    query = query.order_by(Job.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(query)
    jobs = result.scalars().all()
    
    # Get total count
    count_query = select(Job).where(Job.tenant_id == tenant_id)
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
    if not job or job.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return _job_to_response(job)


@router.post("/{job_id}/cancel")
async def cancel_job(
    job_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Cancel a running job (kill switch)"""
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or job.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status not in [JobStatus.PENDING, JobStatus.QUEUED, JobStatus.RUNNING]:
        raise HTTPException(status_code=400, detail="Job cannot be cancelled")
    
    # Send kill signal via Redis
    redis = request.app.state.redis
    await redis.publish(f"job:{job_id}:control", "CANCEL")
    
    job.status = JobStatus.CANCELLED
    job.completed_at = datetime.utcnow()
    
    # Audit log
    audit = AuditLog(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
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


@router.get("/{job_id}/logs")
async def get_job_logs(
    job_id: str,
    log_type: str = Query("all", pattern="^(all|commands|llm)$"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get detailed logs for a job"""
    
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or job.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Return logs from transaction logger
    # In production, this would read from the log store
    return {
        "job_id": job_id,
        "log_type": log_type,
        "logs": [],  # TODO: Implement log retrieval
        "message": "Log retrieval not yet implemented"
    }


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _target_in_scope(target: str, allowed: list, excluded: list) -> bool:
    """Check if target is within scope"""
    # Simple check - in production this would handle CIDRs, wildcards, etc.
    if target in excluded:
        return False
    return target in allowed or any(target.endswith(a) for a in allowed)

def _job_to_response(job: Job) -> JobResponse:
    """Convert Job model to response"""
    return JobResponse(
        id=str(job.id),
        name=job.name,
        description=job.description,
        scope_id=str(job.scope_id) if job.scope_id else None,
        phase=job.phase,
        targets=job.targets,
        status=job.status.value,
        progress=job.progress,
        findings_count=job.findings_count,
        critical_count=job.critical_count,
        high_count=job.high_count,
        tokens_used=job.tokens_used,
        cost_usd=job.cost_usd / 100,  # Convert from cents
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message
    )
