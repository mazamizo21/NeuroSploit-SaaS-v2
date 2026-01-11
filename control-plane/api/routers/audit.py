"""
NeuroSploit SaaS v2 - Audit Router
Audit log access and reporting
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..auth import get_current_user

router = APIRouter()

class AuditLogResponse(BaseModel):
    id: str
    action: str
    resource_type: Optional[str]
    success: bool
    created_at: datetime

@router.get("", response_model=List[AuditLogResponse])
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    action: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List audit logs for tenant"""
    from ..models import AuditLog
    query = select(AuditLog).where(AuditLog.tenant_id == current_user.tenant_id)
    if action:
        query = query.where(AuditLog.action == action)
    query = query.order_by(AuditLog.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    logs = result.scalars().all()
    return [AuditLogResponse(
        id=str(l.id), action=l.action, resource_type=l.resource_type,
        success=l.success, created_at=l.created_at
    ) for l in logs]
