"""
TazoSploit SaaS v2 - WebSocket Router
Real-time updates for attack graphs, findings, job status, and live output
"""

import logging
import asyncio
import json
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from pydantic import BaseModel
import redis.asyncio as redis
import os

from api.utils.redact import redact_text, redact_obj
from api.auth import decode_token, INTERNAL_SERVICE_KEY, CurrentUser
from api.database import engine
from api.models import Job
from sqlalchemy import select
from services.event_service import get_event_service, EventService
from services.attack_graph_service import AttackGraphService

logger = logging.getLogger(__name__)

router = APIRouter()

class ConnectionManager:
    """Manage WebSocket connections"""
    
    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, channel: str):
        """Accept and track connection"""
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = []
        self.active_connections[channel].append(websocket)
        logger.info(f"WebSocket connected to {channel} ({len(self.active_connections[channel])} connections)")
    
    def disconnect(self, websocket: WebSocket, channel: str):
        """Remove connection from tracking"""
        if channel in self.active_connections:
            if websocket in self.active_connections[channel]:
                self.active_connections[channel].remove(websocket)
            if not self.active_connections[channel]:
                del self.active_connections[channel]
        logger.info(f"WebSocket disconnected from {channel}")
    
    async def broadcast(self, channel: str, message: dict):
        """Broadcast message to all connections on channel"""
        if channel in self.active_connections:
            disconnected = []
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_json(message)
                except Exception:
                    disconnected.append(connection)
            
            # Clean up disconnected
            for conn in disconnected:
                self.disconnect(conn, channel)

manager = ConnectionManager()

async def _authorize_ws(
    websocket: WebSocket,
    token: Optional[str],
    expected_tenant: Optional[UUID] = None,
    job_id: Optional[UUID] = None,
):
    """Validate auth token and optional tenant/job ownership."""
    if not token:
        await websocket.close(code=1008)
        return None

    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    # Internal service token
    if token == f"internal-{INTERNAL_SERVICE_KEY}":
        user = CurrentUser(
            id="b0000000-0000-0000-0000-000000000001",
            tenant_id="a0000000-0000-0000-0000-000000000001",
            email="system@tazosploit.local",
            role="admin",
        )
    else:
        try:
            token_data = decode_token(token)
            user = CurrentUser(
                id=token_data.user_id,
                tenant_id=token_data.tenant_id,
                email=token_data.email,
                role=token_data.role,
            )
        except Exception:
            await websocket.close(code=1008)
            return None

    if expected_tenant and str(expected_tenant) != str(user.tenant_id):
        await websocket.close(code=1008)
        return None

    if job_id:
        try:
            async with engine.connect() as conn:
                result = await conn.execute(select(Job.tenant_id).where(Job.id == job_id))
                row = result.first()
                if not row or str(row[0]) != str(user.tenant_id):
                    await websocket.close(code=1008)
                    return None
        except Exception:
            await websocket.close(code=1008)
            return None

    return user

@router.websocket("/jobs/{job_id}/graph")
async def graph_updates_websocket(
    websocket: WebSocket,
    job_id: UUID,
    token: Optional[str] = Query(None)
):
    """
    WebSocket for real-time attack graph updates
    
    Sends events when:
    - New findings discovered
    - Graph nodes added
    - Graph edges created
    - Critical paths identified
    - Risk scores updated
    
    Message format:
    {
        "event_type": "graph.node_added",
        "job_id": "uuid",
        "timestamp": "ISO datetime",
        "data": {...}
    }
    """
    channel = f"job:{job_id}:graph"
    
    user = await _authorize_ws(websocket, token, job_id=job_id)
    if not user:
        return
    
    await manager.connect(websocket, channel)
    event_service = get_event_service()
    
    try:
        await event_service.connect()
        
        # Listen for graph events and forward to WebSocket
        async for event in event_service.subscribe_to_graph(job_id):
            await websocket.send_json(redact_obj(event))
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
        logger.info(f"Client disconnected from graph updates for job {job_id}")
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, channel)

@router.websocket("/jobs/{job_id}/findings")
async def findings_websocket(
    websocket: WebSocket,
    job_id: UUID,
    token: Optional[str] = Query(None)
):
    """
    WebSocket for real-time finding updates
    
    Sends events when new findings are discovered during pentest execution
    
    Message format:
    {
        "event_type": "finding.created",
        "job_id": "uuid",
        "timestamp": "ISO datetime",
        "finding": {
            "title": "...",
            "severity": "...",
            "target": "...",
            ...
        }
    }
    """
    channel = f"job:{job_id}:findings"
    
    user = await _authorize_ws(websocket, token, job_id=job_id)
    if not user:
        return

    await manager.connect(websocket, channel)
    event_service = get_event_service()
    
    try:
        await event_service.connect()
        
        async for event in event_service.subscribe_to_findings(job_id):
            await websocket.send_json(redact_obj(event))
            
            # Also update graph incrementally
            if event.get("event_type") == "finding.created":
                finding = event.get("finding", {})
                # Trigger incremental graph update
                await event_service.publish_graph_updated(
                    job_id,
                    UUID(event.get("tenant_id")),
                    {"trigger": "finding_created", "finding_id": finding.get("id")}
                )
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, channel)

@router.websocket("/tenants/{tenant_id}/jobs")
async def tenant_jobs_websocket(
    websocket: WebSocket,
    tenant_id: UUID,
    token: Optional[str] = Query(None)
):
    """
    WebSocket for tenant job status updates
    
    Sends events for all jobs in a tenant:
    - Job started
    - Job progress updates
    - Job completed
    - Job failed
    
    Message format:
    {
        "event_type": "job.progress",
        "job_id": "uuid",
        "timestamp": "ISO datetime",
        "progress": 45,
        "phase": "EXPLOITATION"
    }
    """
    channel = f"tenant:{tenant_id}:jobs"
    
    user = await _authorize_ws(websocket, token, expected_tenant=tenant_id)
    if not user:
        return

    await manager.connect(websocket, channel)
    event_service = get_event_service()
    
    try:
        await event_service.connect()
        
        async for event in event_service.subscribe(channel):
            await websocket.send_json(redact_obj(event))
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, channel)

@router.websocket("/job/{job_id}")
async def job_output_websocket(
    websocket: WebSocket,
    job_id: str,
    token: Optional[str] = Query(None)
):
    """
    WebSocket for real-time job output (live terminal logs).
    
    Subscribes to Redis pubsub channel `job:{job_id}:output`
    and also reads buffered log lines from Redis list `job:{job_id}:log`.
    
    Message format sent to client:
    {
        "line": "output text here",
        "timestamp": "ISO datetime"
    }
    """
    try:
        job_uuid = UUID(job_id)
    except Exception:
        await websocket.close(code=1008)
        return

    user = await _authorize_ws(websocket, token, job_id=job_uuid)
    if not user:
        return

    channel = f"job:{job_id}:output"
    await manager.connect(websocket, channel)
    
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    try:
        # Create a dedicated Redis connection for pubsub
        redis_client = redis.from_url(redis_url, decode_responses=True)
        
        # First, send any buffered log lines (for clients connecting mid-job)
        try:
            buffered = await redis_client.lrange(f"job:{job_id}:log", 0, -1)
            for line in buffered:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and "line" in obj:
                        obj["line"] = redact_text(str(obj.get("line", "")))
                    await websocket.send_json(obj)
                except Exception:
                    await websocket.send_json({"line": redact_text(str(line))})
        except Exception as e:
            logger.warning(f"Failed to read buffered logs: {e}")
        
        # Subscribe to live output
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(channel)
        
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        if isinstance(data, dict) and "line" in data:
                            data["line"] = redact_text(str(data.get("line", "")))
                        await websocket.send_json(data)
                    except json.JSONDecodeError:
                        await websocket.send_json({"line": redact_text(str(message["data"]))})
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
            await redis_client.close()
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
        logger.info(f"Client disconnected from output for job {job_id}")
    
    except Exception as e:
        logger.error(f"WebSocket output error: {e}")
        manager.disconnect(websocket, channel)


@router.get("/connections")
async def get_active_connections():
    """Get count of active WebSocket connections per channel"""
    return {
        "channels": {
            channel: len(connections) 
            for channel, connections in manager.active_connections.items()
        },
        "total": sum(len(c) for c in manager.active_connections.values())
    }
