"""
TazoSploit SaaS v2 - Agents Router
Tunnel agent management: create tokens, register agents, list/revoke
"""

import uuid
import hashlib
import secrets
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import structlog

from ..database import get_db
from ..models import TunnelAgent
from ..auth import get_current_user

logger = structlog.get_logger()
router = APIRouter()


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)

class AgentTokenResponse(BaseModel):
    id: str
    name: str
    token: str  # Only returned on creation
    install_command: str
    created_at: datetime

class AgentResponse(BaseModel):
    id: str
    name: str
    status: str
    wg_assigned_ip: Optional[str]
    last_heartbeat: Optional[datetime]
    client_info: Optional[dict]
    created_at: datetime

class AgentRegisterRequest(BaseModel):
    token: str
    public_key: str
    client_info: Optional[dict] = None

class AgentRegisterResponse(BaseModel):
    agent_id: str
    gateway_public_key: str
    gateway_endpoint: str
    assigned_ip: str
    allowed_ips: str
    status: str


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("", response_model=AgentTokenResponse)
async def create_agent(
    agent_data: AgentCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Create a new agent token for tunnel connection"""
    tenant_id = current_user.tenant_id
    tenant_uuid = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id

    # Generate one-time token
    raw_token = f"tsploit_{secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    agent = TunnelAgent(
        tenant_id=tenant_uuid,
        name=agent_data.name,
        token_hash=token_hash,
        status="pending",
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)

    gateway_url = request.headers.get("X-Gateway-URL", "http://localhost:8085")

    logger.info("agent_token_created", agent_id=str(agent.id), name=agent_data.name)

    return AgentTokenResponse(
        id=str(agent.id),
        name=agent.name,
        token=raw_token,
        install_command=f"./tazosploit-agent connect --token {raw_token} --gateway {gateway_url}",
        created_at=agent.created_at,
    )


@router.get("", response_model=List[AgentResponse])
async def list_agents(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List all registered agents for tenant"""
    tenant_id = current_user.tenant_id
    tenant_uuid = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id

    result = await db.execute(
        select(TunnelAgent).where(TunnelAgent.tenant_id == tenant_uuid).order_by(TunnelAgent.created_at.desc())
    )
    agents = result.scalars().all()

    return [
        AgentResponse(
            id=str(a.id),
            name=a.name,
            status=a.status,
            wg_assigned_ip=a.wg_assigned_ip,
            last_heartbeat=a.last_heartbeat,
            client_info=a.client_info,
            created_at=a.created_at,
        )
        for a in agents
    ]


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get agent details"""
    agent = await db.get(TunnelAgent, uuid.UUID(agent_id))
    if not agent or str(agent.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Agent not found")

    return AgentResponse(
        id=str(agent.id),
        name=agent.name,
        status=agent.status,
        wg_assigned_ip=agent.wg_assigned_ip,
        last_heartbeat=agent.last_heartbeat,
        client_info=agent.client_info,
        created_at=agent.created_at,
    )


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Revoke/delete an agent"""
    agent = await db.get(TunnelAgent, uuid.UUID(agent_id))
    if not agent or str(agent.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Agent not found")

    # If connected, tell gateway to remove the peer
    if agent.wg_assigned_ip:
        try:
            import httpx
            gateway_url = "http://tazosploit-tunnel:8080"
            async with httpx.AsyncClient() as client:
                await client.delete(f"{gateway_url}/api/v1/tunnel/peers/{agent_id}", timeout=5.0)
        except Exception as e:
            logger.warn("gateway_peer_remove_failed", error=str(e))

    await db.delete(agent)
    await db.commit()

    logger.info("agent_deleted", agent_id=agent_id)
    return {"status": "deleted", "agent_id": agent_id}


@router.post("/register", response_model=AgentRegisterResponse)
async def register_agent(
    reg_data: AgentRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Agent self-registration using one-time token (called by agent binary)"""
    token_hash = hashlib.sha256(reg_data.token.encode()).hexdigest()

    # Find agent by token hash
    result = await db.execute(
        select(TunnelAgent).where(
            and_(
                TunnelAgent.token_hash == token_hash,
                TunnelAgent.token_used == False,
            )
        )
    )
    agent = result.scalars().first()

    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Mark token as used
    agent.token_used = True
    agent.wg_public_key = reg_data.public_key
    agent.client_info = reg_data.client_info or {}
    agent.status = "connecting"
    agent.last_heartbeat = datetime.utcnow()

    # Register with tunnel gateway
    gateway_url = "http://tazosploit-tunnel:8080"
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{gateway_url}/api/v1/tunnel/register",
                json={
                    "agent_id": str(agent.id),
                    "name": agent.name,
                    "public_key": reg_data.public_key,
                    "client_info": reg_data.client_info,
                },
                timeout=10.0,
            )
            if resp.status_code != 200:
                raise Exception(f"Gateway returned {resp.status_code}: {resp.text}")

            gw_resp = resp.json()
            agent.wg_assigned_ip = gw_resp.get("assigned_ip")
            agent.status = "connected"

            await db.commit()
            await db.refresh(agent)

            return AgentRegisterResponse(
                agent_id=str(agent.id),
                gateway_public_key=gw_resp["gateway_public_key"],
                gateway_endpoint=gw_resp["gateway_endpoint"],
                assigned_ip=gw_resp["assigned_ip"],
                allowed_ips=gw_resp.get("allowed_ips", "10.100.0.0/16"),
                status="connected",
            )

    except Exception as e:
        logger.error("agent_registration_failed", error=str(e))
        agent.status = "error"
        await db.commit()
        raise HTTPException(status_code=502, detail=f"Gateway registration failed: {str(e)}")
