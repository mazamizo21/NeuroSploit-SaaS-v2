"""
TazoSploit SaaS v2 - Loot Router
Credentials, hashes, tokens, evidence files
"""

import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

from ..database import get_db
from ..auth import get_current_user, CurrentUser

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────

class LootCreate(BaseModel):
    job_id: str
    loot_type: str = Field(..., description="credential, hash, token, config, db_sample, session")
    source: str = Field(..., description="Where the loot was found")
    value: dict = Field(default_factory=dict, description="The actual loot data")
    description: Optional[str] = None


class LootResponse(BaseModel):
    id: str
    job_id: str
    tenant_id: str
    loot_type: str
    source: str
    value: dict
    description: Optional[str]
    created_at: datetime


class LootListResponse(BaseModel):
    items: List[LootResponse]
    total: int


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=LootListResponse)
async def list_loot(
    job_id: Optional[str] = None,
    loot_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """List loot items for the tenant, filtered by job and optional type."""
    tenant_id = current_user.tenant_id
    if not job_id:
        raise HTTPException(status_code=400, detail="job_id is required")

    conditions = ["tenant_id = :tid"]
    params: dict = {"tid": tenant_id}

    if job_id:
        conditions.append("job_id = :jid")
        params["jid"] = job_id
    if loot_type:
        conditions.append("loot_type = :lt")
        params["lt"] = loot_type

    where = " AND ".join(conditions)

    count_q = text(f"SELECT count(*) FROM loot WHERE {where}")
    count_res = await db.execute(count_q, params)
    total = count_res.scalar() or 0

    q = text(
        f"SELECT id, job_id, tenant_id, loot_type, source, value, description, created_at "
        f"FROM loot WHERE {where} ORDER BY created_at DESC LIMIT :lim OFFSET :off"
    )
    params["lim"] = limit
    params["off"] = offset
    rows = await db.execute(q, params)

    items = []
    for r in rows.mappings():
        items.append(LootResponse(
            id=str(r["id"]),
            job_id=str(r["job_id"]),
            tenant_id=str(r["tenant_id"]),
            loot_type=r["loot_type"],
            source=r["source"],
            value=r["value"] if isinstance(r["value"], dict) else {},
            description=r["description"],
            created_at=r["created_at"],
        ))

    return LootListResponse(items=items, total=total)


@router.post("", response_model=LootResponse, status_code=201)
async def create_loot(
    body: LootCreate,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Add a loot item."""
    tenant_id = current_user.tenant_id
    loot_id = str(uuid.uuid4())
    now = datetime.utcnow()

    import json as json_mod
    await db.execute(
        text(
            "INSERT INTO loot (id, job_id, tenant_id, loot_type, source, value, description, created_at) "
            "VALUES (:id, :jid, :tid, :lt, :src, cast(:val as jsonb), :desc, :ts)"
        ),
        {
            "id": loot_id,
            "jid": body.job_id,
            "tid": tenant_id,
            "lt": body.loot_type,
            "src": body.source,
            "val": json_mod.dumps(body.value),
            "desc": body.description,
            "ts": now,
        },
    )
    await db.commit()

    return LootResponse(
        id=loot_id,
        job_id=body.job_id,
        tenant_id=tenant_id,
        loot_type=body.loot_type,
        source=body.source,
        value=body.value,
        description=body.description,
        created_at=now,
    )


@router.get("/stats")
async def loot_stats(
    job_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get loot statistics for the tenant, filtered by job."""
    tid = current_user.tenant_id
    if not job_id:
        raise HTTPException(status_code=400, detail="job_id is required")
    conditions = ["tenant_id = :tid"]
    params: dict = {"tid": tid}

    if job_id:
        conditions.append("job_id = :jid")
        params["jid"] = job_id

    where = " AND ".join(conditions)
    q = text(
        f"SELECT loot_type, count(*) as cnt FROM loot WHERE {where} GROUP BY loot_type"
    )
    rows = await db.execute(q, params)
    stats = {r["loot_type"]: r["cnt"] for r in rows.mappings()}
    total = sum(stats.values())
    return {"total": total, "by_type": stats}
