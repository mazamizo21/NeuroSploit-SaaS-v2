"""
TazoSploit SaaS v2 - Policies Router
Security policy management
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..auth import get_current_user

router = APIRouter()

class PolicyResponse(BaseModel):
    id: str
    name: str
    allowed_tools: List[str]
    max_intensity: str
    is_active: bool

@router.get("", response_model=List[PolicyResponse])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all policies for tenant"""
    from ..models import Policy
    result = await db.execute(
        select(Policy).where(Policy.tenant_id == current_user.tenant_id)
    )
    policies = result.scalars().all()
    return [PolicyResponse(
        id=str(p.id), name=p.name, allowed_tools=p.allowed_tools or [],
        max_intensity=p.max_intensity, is_active=p.is_active
    ) for p in policies]
