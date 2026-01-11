"""
NeuroSploit SaaS v2 - WebSocket Router
Real-time updates for attack graphs, findings, and job status
"""

import logging
import asyncio
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from pydantic import BaseModel

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
    
    # TODO: Validate token for auth
    # For now, accept all connections
    
    await manager.connect(websocket, channel)
    event_service = get_event_service()
    
    try:
        await event_service.connect()
        
        # Listen for graph events and forward to WebSocket
        async for event in event_service.subscribe_to_graph(job_id):
            await websocket.send_json(event)
    
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
    
    await manager.connect(websocket, channel)
    event_service = get_event_service()
    
    try:
        await event_service.connect()
        
        async for event in event_service.subscribe_to_findings(job_id):
            await websocket.send_json(event)
            
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
    
    await manager.connect(websocket, channel)
    event_service = get_event_service()
    
    try:
        await event_service.connect()
        
        async for event in event_service.subscribe(channel):
            await websocket.send_json(event)
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
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
