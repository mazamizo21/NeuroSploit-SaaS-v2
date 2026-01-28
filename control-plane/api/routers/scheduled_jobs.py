"""
TazoSploit SaaS v2 - Scheduled Jobs Router
API endpoints for continuous scanning configuration
"""

import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..database import get_db
from ..models import ScheduledJob, Tenant
from ..auth import get_current_user
from services.scheduler_service import SchedulerService, CRON_PATTERNS

router = APIRouter()

# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ScheduledJobCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    schedule: str = Field(..., description="Cron expression (e.g., '0 2 * * *')")
    timezone: str = Field(default="UTC")
    job_template: dict = Field(..., description="Job configuration to run")
    is_active: bool = True

class ScheduledJobUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    schedule: Optional[str] = None
    timezone: Optional[str] = None
    job_template: Optional[dict] = None
    is_active: Optional[bool] = None
    is_paused: Optional[bool] = None

class ScheduledJobResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    schedule: str
    schedule_description: str
    timezone: str
    job_template: dict
    is_active: bool
    is_paused: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    total_runs: int
    successful_runs: int
    failed_runs: int
    created_at: datetime
    updated_at: datetime

class ScheduledJobListResponse(BaseModel):
    scheduled_jobs: List[ScheduledJobResponse]
    total: int

class CronPatternsResponse(BaseModel):
    patterns: dict

# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/patterns", response_model=CronPatternsResponse)
async def get_cron_patterns():
    """Get common cron patterns"""
    return {"patterns": CRON_PATTERNS}

@router.post("", response_model=ScheduledJobResponse)
async def create_scheduled_job(
    job_data: ScheduledJobCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new scheduled job for continuous scanning"""
    
    tenant_id = current_user.tenant_id
    
    # Validate cron expression
    if not SchedulerService.parse_cron(job_data.schedule):
        raise HTTPException(status_code=400, detail="Invalid cron expression")
    
    # Calculate next run
    try:
        next_run = SchedulerService.calculate_next_run(
            job_data.schedule,
            timezone=job_data.timezone
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to calculate next run: {str(e)}")
    
    # Create scheduled job
    scheduled_job = ScheduledJob(
        tenant_id=tenant_id,
        created_by=current_user.id,
        name=job_data.name,
        description=job_data.description,
        schedule=job_data.schedule,
        timezone=job_data.timezone,
        job_template=job_data.job_template,
        is_active=job_data.is_active,
        next_run=next_run
    )
    
    db.add(scheduled_job)
    await db.commit()
    await db.refresh(scheduled_job)
    
    return _build_response(scheduled_job)

@router.get("", response_model=ScheduledJobListResponse)
async def list_scheduled_jobs(
    active_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all scheduled jobs for tenant"""
    
    tenant_id = current_user.tenant_id
    
    query = select(ScheduledJob).where(ScheduledJob.tenant_id == tenant_id)
    
    if active_only:
        query = query.where(ScheduledJob.is_active == True)
    
    result = await db.execute(query)
    scheduled_jobs = result.scalars().all()
    
    return {
        "scheduled_jobs": [_build_response(sj) for sj in scheduled_jobs],
        "total": len(scheduled_jobs)
    }

@router.get("/{scheduled_job_id}", response_model=ScheduledJobResponse)
async def get_scheduled_job(
    scheduled_job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get scheduled job details"""
    
    tenant_id = current_user.tenant_id
    
    scheduled_job = await db.get(ScheduledJob, uuid.UUID(scheduled_job_id))
    
    if not scheduled_job or scheduled_job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    
    return _build_response(scheduled_job)

@router.put("/{scheduled_job_id}", response_model=ScheduledJobResponse)
async def update_scheduled_job(
    scheduled_job_id: str,
    job_data: ScheduledJobUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update scheduled job"""
    
    tenant_id = current_user.tenant_id
    
    scheduled_job = await db.get(ScheduledJob, uuid.UUID(scheduled_job_id))
    
    if not scheduled_job or scheduled_job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    
    # Update fields
    if job_data.name is not None:
        scheduled_job.name = job_data.name
    if job_data.description is not None:
        scheduled_job.description = job_data.description
    if job_data.schedule is not None:
        if not SchedulerService.parse_cron(job_data.schedule):
            raise HTTPException(status_code=400, detail="Invalid cron expression")
        scheduled_job.schedule = job_data.schedule
        # Recalculate next run
        scheduled_job.next_run = SchedulerService.calculate_next_run(
            job_data.schedule,
            timezone=scheduled_job.timezone
        )
    if job_data.timezone is not None:
        scheduled_job.timezone = job_data.timezone
    if job_data.job_template is not None:
        scheduled_job.job_template = job_data.job_template
    if job_data.is_active is not None:
        scheduled_job.is_active = job_data.is_active
    if job_data.is_paused is not None:
        scheduled_job.is_paused = job_data.is_paused
    
    scheduled_job.updated_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(scheduled_job)
    
    return _build_response(scheduled_job)

@router.delete("/{scheduled_job_id}")
async def delete_scheduled_job(
    scheduled_job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete scheduled job"""
    
    tenant_id = current_user.tenant_id
    
    scheduled_job = await db.get(ScheduledJob, uuid.UUID(scheduled_job_id))
    
    if not scheduled_job or scheduled_job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    
    await db.delete(scheduled_job)
    await db.commit()
    
    return {"message": "Scheduled job deleted"}

@router.post("/{scheduled_job_id}/pause")
async def pause_scheduled_job(
    scheduled_job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Pause scheduled job"""
    
    tenant_id = current_user.tenant_id
    
    scheduled_job = await db.get(ScheduledJob, uuid.UUID(scheduled_job_id))
    
    if not scheduled_job or scheduled_job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    
    scheduled_job.is_paused = True
    scheduled_job.updated_at = datetime.utcnow()
    
    await db.commit()
    
    return {"message": "Scheduled job paused"}

@router.post("/{scheduled_job_id}/resume")
async def resume_scheduled_job(
    scheduled_job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Resume scheduled job"""
    
    tenant_id = current_user.tenant_id
    
    scheduled_job = await db.get(ScheduledJob, uuid.UUID(scheduled_job_id))
    
    if not scheduled_job or scheduled_job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    
    scheduled_job.is_paused = False
    scheduled_job.updated_at = datetime.utcnow()
    
    # Recalculate next run
    scheduled_job.next_run = SchedulerService.calculate_next_run(
        scheduled_job.schedule,
        timezone=scheduled_job.timezone
    )
    
    await db.commit()
    
    return {"message": "Scheduled job resumed"}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _build_response(scheduled_job: ScheduledJob) -> dict:
    """Build scheduled job response"""
    return {
        "id": str(scheduled_job.id),
        "name": scheduled_job.name,
        "description": scheduled_job.description,
        "schedule": scheduled_job.schedule,
        "schedule_description": SchedulerService.get_schedule_description(scheduled_job.schedule),
        "timezone": scheduled_job.timezone,
        "job_template": scheduled_job.job_template,
        "is_active": scheduled_job.is_active,
        "is_paused": scheduled_job.is_paused,
        "last_run": scheduled_job.last_run,
        "next_run": scheduled_job.next_run,
        "total_runs": scheduled_job.total_runs,
        "successful_runs": scheduled_job.successful_runs,
        "failed_runs": scheduled_job.failed_runs,
        "created_at": scheduled_job.created_at,
        "updated_at": scheduled_job.updated_at
    }
