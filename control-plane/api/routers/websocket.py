"""
TazoSploit SaaS v2 - WebSocket Router
Real-time updates for attack graphs, findings, job status, and live output
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from pydantic import BaseModel
import redis.asyncio as redis
import os
import hashlib
import structlog

from api.utils.redact import redact_text, redact_obj
from api.auth import decode_token, INTERNAL_SERVICE_KEY, CurrentUser
from api.database import engine
from api.models import Job, JobStatus
from sqlalchemy import select, update as sql_update
from services.event_service import get_event_service, EventService
from services.attack_graph_service import AttackGraphService

logger = structlog.get_logger()

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
    # Never log the raw token (it may be a JWT or internal service key).
    # Log only presence/shape metadata for debugging.
    try:
        ws_path = getattr(getattr(websocket, "url", None), "path", "") or ""
    except Exception:
        ws_path = ""
    try:
        ws_client = getattr(websocket, "client", None)
        ws_client_ip = getattr(ws_client, "host", "") if ws_client else ""
    except Exception:
        ws_client_ip = ""

    if not token:
        logger.warning(
            "ws_authorize_denied_missing_token",
            path=ws_path,
            client_ip=ws_client_ip,
            job_id=str(job_id) if job_id else None,
            expected_tenant=str(expected_tenant) if expected_tenant else None,
        )
        await websocket.close(code=1008)
        return None

    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    token_len = len(token)
    token_starts_internal = token.startswith("internal-")
    token_is_internal = token == f"internal-{INTERNAL_SERVICE_KEY}"
    token_fingerprint = ""
    try:
        token_fingerprint = hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()[:12]
    except Exception:
        token_fingerprint = ""

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
            logger.warning(
                "ws_authorize_denied_token_invalid",
                path=ws_path,
                client_ip=ws_client_ip,
                token_len=token_len,
                starts_internal=token_starts_internal,
                internal_match=token_is_internal,
                token_fp=token_fingerprint,
            )
            await websocket.close(code=1008)
            return None

    if expected_tenant and str(expected_tenant) != str(user.tenant_id):
        logger.warning(
            "ws_authorize_denied_tenant_mismatch",
            path=ws_path,
            client_ip=ws_client_ip,
            expected_tenant=str(expected_tenant),
            user_tenant=str(user.tenant_id),
            job_id=str(job_id) if job_id else None,
            token_fp=token_fingerprint,
        )
        await websocket.close(code=1008)
        return None

    if job_id:
        try:
            async with engine.connect() as conn:
                result = await conn.execute(select(Job.tenant_id).where(Job.id == job_id))
                row = result.first()
                if not row or str(row[0]) != str(user.tenant_id):
                    job_tenant = str(row[0]) if row and row[0] else ""
                    logger.warning(
                        "ws_authorize_denied_job_tenant_mismatch",
                        path=ws_path,
                        client_ip=ws_client_ip,
                        job_id=str(job_id),
                        job_tenant=job_tenant,
                        user_tenant=str(user.tenant_id),
                        token_fp=token_fingerprint,
                    )
                    await websocket.close(code=1008)
                    return None
        except Exception:
            logger.exception(
                "ws_authorize_denied_job_lookup_error",
                path=ws_path,
                client_ip=ws_client_ip,
                job_id=str(job_id),
                token_fp=token_fingerprint,
            )
            await websocket.close(code=1008)
            return None

    logger.info(
        "ws_authorize_ok",
        path=ws_path,
        client_ip=ws_client_ip,
        user_tenant=str(user.tenant_id),
        job_id=str(job_id) if job_id else None,
        expected_tenant=str(expected_tenant) if expected_tenant else None,
        internal_match=token_is_internal,
        token_fp=token_fingerprint,
    )
    return user


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_output_message(raw_data) -> dict:
    """Normalize legacy output-channel payloads into typed chat events."""
    if isinstance(raw_data, dict):
        if isinstance(raw_data.get("type"), str):
            return raw_data
        if "line" in raw_data:
            return {
                "type": "output",
                "payload": {
                    "line": redact_text(str(raw_data.get("line", ""))),
                    "timestamp": raw_data.get("timestamp") or _now_iso(),
                },
                "timestamp": raw_data.get("timestamp") or _now_iso(),
            }
    return {
        "type": "output",
        "payload": {
            "line": redact_text(str(raw_data)),
            "timestamp": _now_iso(),
        },
        "timestamp": _now_iso(),
    }


@router.websocket("/jobs/{job_id}/chat")
async def job_chat_websocket(
    websocket: WebSocket,
    job_id: str,
    token: Optional[str] = Query(None),
):
    """Bidirectional chat channel for live guidance and structured agent events."""
    try:
        ws_client = getattr(websocket, "client", None)
        ws_client_ip = getattr(ws_client, "host", "") if ws_client else ""
    except Exception:
        ws_client_ip = ""
    logger.info(
        "ws_chat_connect_attempt",
        client_ip=ws_client_ip,
        job_id=str(job_id),
        token_present=bool(token),
        token_len=len(token or ""),
    )
    try:
        job_uuid = UUID(job_id)
    except Exception:
        await websocket.close(code=1008)
        return

    user = await _authorize_ws(websocket, token, job_id=job_uuid)
    if not user:
        return

    await websocket.accept()

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_client = redis.from_url(redis_url, decode_responses=True)
    redis_sub = redis.from_url(redis_url, decode_responses=True)
    pubsub = redis_sub.pubsub()
    output_channel = f"job:{job_id}:output"
    events_channel = f"job:{job_id}:events"
    guidance_key = f"job:{job_id}:guidance"
    guidance_history_key = f"job:{job_id}:guidance_history"
    approval_key = f"job:{job_id}:approval_response"
    answer_key = f"job:{job_id}:user_answer"
    stop_key = f"job:{job_id}:stop_signal"

    await pubsub.subscribe(output_channel, events_channel)

    await websocket.send_json(
        {
            "type": "connected",
            "payload": {"job_id": job_id},
            "timestamp": _now_iso(),
        }
    )

    async def forward_agent_events():
        try:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                raw = message.get("data")
                if raw is None:
                    continue
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = raw

                outbound = _format_output_message(parsed)
                try:
                    await websocket.send_json(redact_obj(outbound))
                except Exception:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"chat_forward_error job={job_id} error={e}")

    forward_task = asyncio.create_task(forward_agent_events())

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": {"message": "Invalid JSON message", "recoverable": True},
                        "timestamp": _now_iso(),
                    }
                )
                continue

            msg_type = str(msg.get("type", "")).strip().lower()
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                payload = {}

            if msg_type == "guidance":
                message_text = str(payload.get("message", "")).strip()
                if not message_text:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": {"message": "guidance.message is required", "recoverable": True},
                            "timestamp": _now_iso(),
                        }
                    )
                    continue

                entry = {
                    "message": message_text,
                    "source": "user",
                    "timestamp": _now_iso(),
                }
                queue_pos = await redis_client.rpush(guidance_key, json.dumps(entry, ensure_ascii=True))
                await redis_client.expire(guidance_key, 86400)
                await redis_client.rpush(guidance_history_key, json.dumps(entry, ensure_ascii=True))
                await redis_client.ltrim(guidance_history_key, -100, -1)
                await redis_client.expire(guidance_history_key, 86400)

                await websocket.send_json(
                    {
                        "type": "guidance_ack",
                        "payload": {
                            "message": message_text,
                            "queue_position": int(queue_pos or 0),
                        },
                        "timestamp": _now_iso(),
                    }
                )

            elif msg_type == "approval":
                approval = {
                    "decision": str(payload.get("decision", "approve")),
                    "modification": payload.get("modification"),
                    "request_id": payload.get("request_id"),
                    "timestamp": _now_iso(),
                }
                await redis_client.set(approval_key, json.dumps(approval, ensure_ascii=True), ex=86400)
                await websocket.send_json(
                    {
                        "type": "approval_ack",
                        "payload": {"request_id": approval.get("request_id"), "decision": approval.get("decision")},
                        "timestamp": _now_iso(),
                    }
                )

            elif msg_type == "answer":
                answer = {
                    "answer": str(payload.get("answer", "")),
                    "question_id": payload.get("question_id"),
                    "timestamp": _now_iso(),
                }
                await redis_client.set(answer_key, json.dumps(answer, ensure_ascii=True), ex=86400)
                await websocket.send_json(
                    {
                        "type": "answer_ack",
                        "payload": {"question_id": answer.get("question_id")},
                        "timestamp": _now_iso(),
                    }
                )

            elif msg_type == "stop":
                await redis_client.set(stop_key, "1", ex=86400)
                await websocket.send_json(
                    {
                        "type": "stopped",
                        "payload": {"requested": True},
                        "timestamp": _now_iso(),
                    }
                )

            elif msg_type == "resume":
                # Resume means: clear stop + terminal flags, enqueue job, set resume flag.
                # Best-effort also resets DB job status to pending so the UI reflects the new run.
                try:
                    async with engine.connect() as conn:
                        row = (await conn.execute(select(Job.status, Job.tenant_id).where(Job.id == job_uuid))).first()
                except Exception:
                    row = None

                if not row:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": {"message": "Job not found", "recoverable": True},
                            "timestamp": _now_iso(),
                        }
                    )
                    continue

                status_val = row[0].value if hasattr(row[0], "value") else str(row[0])
                tenant_val = str(row[1])
                if status_val not in {"paused", "completed", "failed", "cancelled", "timeout"}:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": {
                                "message": f"Job is not resumable from status={status_val}",
                                "recoverable": True,
                            },
                            "timestamp": _now_iso(),
                        }
                    )
                    continue

                # Clear stop + terminal flags so scheduler/agent can run again.
                try:
                    await redis_client.delete(stop_key)
                except Exception:
                    pass
                try:
                    await redis_client.delete(f"job:{job_id}:terminal")
                except Exception:
                    pass

                # Mark this as a resume so the worker loads checkpoint/session.
                try:
                    await redis_client.set(f"job:{job_id}:resume", "true", ex=86400)
                except Exception:
                    pass

                # Reset job state in DB to pending (best-effort).
                try:
                    async with engine.begin() as conn:
                        await conn.execute(
                            sql_update(Job)
                            .where(Job.id == job_uuid)
                            .values(
                                status=JobStatus.pending,
                                started_at=None,
                                completed_at=None,
                                worker_id=None,
                                container_id=None,
                                progress=0,
                                result=None,
                                error_message=None,
                            )
                        )
                except Exception as e:
                    logger.warning(f"chat_resume_db_reset_failed job={job_id} error={e}")

                # Enqueue back onto the tenant queue.
                try:
                    await redis_client.lpush(f"tenant:{tenant_val}:job_queue", job_id)
                except Exception as e:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "payload": {"message": f"Failed to enqueue job: {e}", "recoverable": True},
                            "timestamp": _now_iso(),
                        }
                    )
                    continue

                await websocket.send_json(
                    {
                        "type": "resumed",
                        "payload": {"requested": True, "status": status_val},
                        "timestamp": _now_iso(),
                    }
                )

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong", "payload": {}, "timestamp": _now_iso()})

            else:
                await websocket.send_json(
                    {
                        "type": "error",
                        "payload": {"message": f"Unsupported message type: {msg_type}", "recoverable": True},
                        "timestamp": _now_iso(),
                    }
                )

    except WebSocketDisconnect:
        logger.info(f"Chat WebSocket disconnected for job {job_id}")
    except Exception as e:
        logger.error(f"Chat WebSocket error for job {job_id}: {e}")
    finally:
        forward_task.cancel()
        try:
            await pubsub.unsubscribe(output_channel, events_channel)
        except Exception:
            pass
        try:
            await pubsub.close()
        except Exception:
            pass
        try:
            await redis_sub.close()
        except Exception:
            pass
        try:
            await redis_client.close()
        except Exception:
            pass

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
