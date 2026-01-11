"""
NeuroSploit SaaS v2 - Event Service
Real-time event publishing and subscription via Redis Pub/Sub
"""

import json
import logging
import asyncio
from typing import AsyncGenerator, Dict, Any, Optional, Callable
from uuid import UUID
from datetime import datetime
import redis.asyncio as redis

logger = logging.getLogger(__name__)

class EventService:
    """
    Real-time event service using Redis Pub/Sub
    
    Enables live updates for attack graphs, findings, and job status
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis_client: Optional[redis.Redis] = None
        self.pubsub: Optional[redis.client.PubSub] = None
        self._connected = False
    
    async def connect(self):
        """Establish Redis connection"""
        if not self._connected:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            self.pubsub = self.redis_client.pubsub()
            self._connected = True
            logger.info(f"EventService connected to Redis at {self.redis_url}")
    
    async def disconnect(self):
        """Close Redis connection"""
        if self._connected:
            if self.pubsub:
                await self.pubsub.close()
            if self.redis_client:
                await self.redis_client.close()
            self._connected = False
            logger.info("EventService disconnected from Redis")
    
    async def publish(self, channel: str, event: Dict[str, Any]) -> int:
        """
        Publish event to channel
        
        Args:
            channel: Redis channel name
            event: Event data dictionary
        
        Returns:
            Number of subscribers that received the message
        """
        if not self._connected:
            await self.connect()
        
        event["timestamp"] = datetime.utcnow().isoformat()
        message = json.dumps(event)
        subscribers = await self.redis_client.publish(channel, message)
        
        logger.debug(f"Published to {channel}: {event.get('event_type', 'unknown')} ({subscribers} subscribers)")
        return subscribers
    
    async def subscribe(self, channel: str) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Subscribe to channel and yield events
        
        Args:
            channel: Redis channel name
        
        Yields:
            Event dictionaries as they arrive
        """
        if not self._connected:
            await self.connect()
        
        await self.pubsub.subscribe(channel)
        logger.info(f"Subscribed to channel: {channel}")
        
        try:
            async for message in self.pubsub.listen():
                if message["type"] == "message":
                    try:
                        event = json.loads(message["data"])
                        yield event
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON in message: {message['data']}")
        finally:
            await self.pubsub.unsubscribe(channel)
    
    # ==========================================================================
    # JOB EVENTS
    # ==========================================================================
    
    async def publish_job_started(self, job_id: UUID, tenant_id: UUID) -> int:
        """Publish job started event"""
        return await self.publish(
            f"tenant:{tenant_id}:jobs",
            {
                "event_type": "job.started",
                "job_id": str(job_id),
                "tenant_id": str(tenant_id)
            }
        )
    
    async def publish_job_progress(
        self, 
        job_id: UUID, 
        tenant_id: UUID,
        progress: int,
        phase: str
    ) -> int:
        """Publish job progress update"""
        return await self.publish(
            f"tenant:{tenant_id}:jobs",
            {
                "event_type": "job.progress",
                "job_id": str(job_id),
                "tenant_id": str(tenant_id),
                "progress": progress,
                "phase": phase
            }
        )
    
    async def publish_job_completed(
        self,
        job_id: UUID,
        tenant_id: UUID,
        findings_count: int
    ) -> int:
        """Publish job completed event"""
        return await self.publish(
            f"tenant:{tenant_id}:jobs",
            {
                "event_type": "job.completed",
                "job_id": str(job_id),
                "tenant_id": str(tenant_id),
                "findings_count": findings_count
            }
        )
    
    # ==========================================================================
    # FINDING EVENTS
    # ==========================================================================
    
    async def publish_finding_created(
        self,
        job_id: UUID,
        tenant_id: UUID,
        finding: Dict[str, Any]
    ) -> int:
        """Publish finding created event - triggers graph update"""
        return await self.publish(
            f"job:{job_id}:findings",
            {
                "event_type": "finding.created",
                "job_id": str(job_id),
                "tenant_id": str(tenant_id),
                "finding": finding
            }
        )
    
    async def subscribe_to_findings(
        self,
        job_id: UUID
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Subscribe to findings for a job"""
        channel = f"job:{job_id}:findings"
        async for event in self.subscribe(channel):
            yield event
    
    # ==========================================================================
    # GRAPH EVENTS
    # ==========================================================================
    
    async def publish_graph_updated(
        self,
        job_id: UUID,
        tenant_id: UUID,
        update: Dict[str, Any]
    ) -> int:
        """Publish graph update event"""
        return await self.publish(
            f"job:{job_id}:graph",
            {
                "event_type": "graph.updated",
                "job_id": str(job_id),
                "tenant_id": str(tenant_id),
                "update": update
            }
        )
    
    async def publish_graph_node_added(
        self,
        job_id: UUID,
        tenant_id: UUID,
        node: Dict[str, Any]
    ) -> int:
        """Publish node added event"""
        return await self.publish(
            f"job:{job_id}:graph",
            {
                "event_type": "graph.node_added",
                "job_id": str(job_id),
                "tenant_id": str(tenant_id),
                "node": node
            }
        )
    
    async def publish_graph_edge_added(
        self,
        job_id: UUID,
        tenant_id: UUID,
        edge: Dict[str, Any]
    ) -> int:
        """Publish edge added event"""
        return await self.publish(
            f"job:{job_id}:graph",
            {
                "event_type": "graph.edge_added",
                "job_id": str(job_id),
                "tenant_id": str(tenant_id),
                "edge": edge
            }
        )
    
    async def publish_critical_path_found(
        self,
        job_id: UUID,
        tenant_id: UUID,
        path: Dict[str, Any]
    ) -> int:
        """Publish critical path found event"""
        return await self.publish(
            f"job:{job_id}:graph",
            {
                "event_type": "graph.critical_path_found",
                "job_id": str(job_id),
                "tenant_id": str(tenant_id),
                "path": path
            }
        )
    
    async def subscribe_to_graph(
        self,
        job_id: UUID
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Subscribe to graph updates for a job"""
        channel = f"job:{job_id}:graph"
        async for event in self.subscribe(channel):
            yield event


# Global event service instance
_event_service: Optional[EventService] = None

def get_event_service() -> EventService:
    """Get or create event service singleton"""
    global _event_service
    if _event_service is None:
        import os
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        _event_service = EventService(redis_url)
    return _event_service
