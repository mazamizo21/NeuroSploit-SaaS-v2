"""
NeuroSploit SaaS v2 - Tenants Router
Tenant management and configuration
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..auth import get_current_user

router = APIRouter()

class TenantResponse(BaseModel):
    id: str
    name: str
    tier: str
    max_concurrent_jobs: int
    max_scopes: int

@router.get("/me", response_model=TenantResponse)
async def get_current_tenant(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get current tenant details"""
    from ..models import Tenant
    tenant = await db.get(Tenant, current_user.tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return TenantResponse(
        id=str(tenant.id),
        name=tenant.name,
        tier=tenant.tier.value,
        max_concurrent_jobs=tenant.max_concurrent_jobs,
        max_scopes=tenant.max_scopes
    )
