"""
TazoSploit SaaS v2 - Scopes Router
Target scope management and authorization
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..auth import get_current_user

router = APIRouter()

class ScopeCreate(BaseModel):
    name: str
    description: Optional[str] = None
    targets: List[str]
    excluded_targets: List[str] = []
    allowed_phases: List[str] = ["RECON", "VULN_SCAN"]
    max_intensity: str = "medium"

class ScopeResponse(BaseModel):
    id: str
    name: str
    targets: List[str]
    is_active: bool

@router.get("", response_model=List[ScopeResponse])
async def list_scopes(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all scopes for tenant"""
    from ..models import Scope
    result = await db.execute(
        select(Scope).where(Scope.tenant_id == current_user.tenant_id)
    )
    scopes = result.scalars().all()
    return [ScopeResponse(
        id=str(s.id), name=s.name, targets=s.targets, is_active=s.is_active
    ) for s in scopes]

@router.post("", response_model=ScopeResponse)
async def create_scope(
    scope_data: ScopeCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new scope"""
    from ..models import Scope
    scope = Scope(
        tenant_id=current_user.tenant_id,
        name=scope_data.name,
        description=scope_data.description,
        targets=scope_data.targets,
        excluded_targets=scope_data.excluded_targets,
        allowed_phases=scope_data.allowed_phases,
        max_intensity=scope_data.max_intensity,
        is_active=True
    )
    db.add(scope)
    await db.commit()
    return ScopeResponse(
        id=str(scope.id), name=scope.name, targets=scope.targets, is_active=scope.is_active
    )
