"""
TazoSploit SaaS v2 - Terminal Router
WebSocket terminal sessions into Kali containers via tmux
"""

import uuid
import asyncio
import json
from datetime import datetime
from typing import Optional, List
import shlex
from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from ..database import get_db
from ..auth import get_current_user, CurrentUser, decode_token

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────

class SessionCreate(BaseModel):
    job_id: Optional[str] = None
    container_name: Optional[str] = None
    label: Optional[str] = None
    start_command: Optional[str] = None
    record_output: Optional[bool] = True


class SessionResponse(BaseModel):
    id: str
    tenant_id: str
    job_id: Optional[str]
    container_name: str
    tmux_session: str
    label: Optional[str]
    status: str
    created_at: datetime


class SessionListResponse(BaseModel):
    sessions: List[SessionResponse]
    total: int


# ── REST Endpoints ───────────────────────────────────────────────────────────

@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """List active terminal sessions."""
    tid = current_user.tenant_id
    rows = await db.execute(
        text("SELECT * FROM active_sessions WHERE tenant_id = :tid ORDER BY created_at DESC"),
        {"tid": tid},
    )
    sessions = []
    for r in rows.mappings():
        sessions.append(SessionResponse(
            id=str(r["id"]),
            tenant_id=str(r["tenant_id"]),
            job_id=str(r["job_id"]) if r.get("job_id") else None,
            container_name=r["container_name"],
            tmux_session=r["tmux_session"],
            label=r.get("label"),
            status=r["status"],
            created_at=r["created_at"],
        ))
    return SessionListResponse(sessions=sessions, total=len(sessions))


@router.post("/sessions", response_model=SessionResponse, status_code=201)
async def create_session(
    body: SessionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Create a new terminal session (starts tmux in a Kali container)."""
    import docker

    tid = current_user.tenant_id
    session_id = str(uuid.uuid4())
    tmux_name = f"ts-{session_id[:8]}"

    # Find a kali container
    client = docker.from_env()
    container_name = body.container_name
    if not container_name:
        containers = client.containers.list(status="running")
        kali = [c for c in containers if "kali" in c.name.lower()]
        if not kali:
            raise HTTPException(status_code=503, detail="No Kali containers running")
        container_name = kali[0].name

    # Start tmux session in the container
    try:
        container = client.containers.get(container_name)
        tmux_cmd = ["tmux", "new-session", "-d", "-s", tmux_name]
        start_command = (body.start_command or "").strip()
        if start_command:
            record_output = True if body.record_output is None else bool(body.record_output)
            if body.job_id and record_output:
                # Fix #2: Sanitize job_id to prevent path traversal/injection
                import re as _re_sanitize
                safe_job_id = _re_sanitize.sub(r'[^a-zA-Z0-9\-]', '', str(body.job_id))
                record_dir = f"/pentest/output/{safe_job_id}/terminal_sessions"
                record_path = f"{record_dir}/{session_id}.log"
                container.exec_run(cmd=["mkdir", "-p", record_dir], workdir="/pentest")
                start_command = f"script -q -f {shlex.quote(record_path)} -c {shlex.quote(start_command)}"
            tmux_cmd.extend(["bash", "-lc", start_command])
        else:
            tmux_cmd.extend(["bash", "-l"])
        container.exec_run(cmd=tmux_cmd, workdir="/pentest")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create tmux session: {e}")

    now = datetime.utcnow()
    await db.execute(
        text(
            "INSERT INTO active_sessions (id, tenant_id, job_id, container_name, tmux_session, label, status, created_at) "
            "VALUES (:id, :tid, :jid, :cn, :ts, :lbl, 'active', :now)"
        ),
        {
            "id": session_id,
            "tid": tid,
            "jid": body.job_id,
            "cn": container_name,
            "ts": tmux_name,
            "lbl": body.label or f"Session {session_id[:8]}",
            "now": now,
        },
    )

    return SessionResponse(
        id=session_id,
        tenant_id=tid,
        job_id=body.job_id,
        container_name=container_name,
        tmux_session=tmux_name,
        label=body.label or f"Session {session_id[:8]}",
        status="active",
        created_at=now,
    )


@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Kill a terminal session."""
    import docker

    tid = current_user.tenant_id
    row = await db.execute(
        text("SELECT * FROM active_sessions WHERE id = :id AND tenant_id = :tid"),
        {"id": session_id, "tid": tid},
    )
    session = row.mappings().first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Kill tmux session
    try:
        client = docker.from_env()
        container = client.containers.get(session["container_name"])
        container.exec_run(cmd=["tmux", "kill-session", "-t", session["tmux_session"]])
    except Exception:
        pass

    await db.execute(
        text("UPDATE active_sessions SET status = 'closed' WHERE id = :id"),
        {"id": session_id},
    )

    return {"status": "closed", "session_id": session_id}


# ── WebSocket Terminal ───────────────────────────────────────────────────────

@router.websocket("/ws/terminal/{session_id}")
async def terminal_ws(websocket: WebSocket, session_id: str):
    """
    Bidirectional WebSocket terminal.
    Pipes stdin/stdout between the browser and a tmux session in a Kali container.
    Auth via ?token=JWT query param.
    """
    await websocket.accept()

    # Authenticate via query param
    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_json({"error": "Missing token"})
        await websocket.close()
        return

    try:
        user = decode_token(token)
    except Exception:
        await websocket.send_json({"error": "Invalid token"})
        await websocket.close()
        return

    # Look up session
    from ..database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        row = await db.execute(
            text("SELECT * FROM active_sessions WHERE id = :id AND tenant_id = :tid AND status = 'active'"),
            {"id": session_id, "tid": user.tenant_id},
        )
        session = row.mappings().first()

    if not session:
        await websocket.send_json({"error": "Session not found or inactive"})
        await websocket.close()
        return

    container_name = session["container_name"]
    tmux_session = session["tmux_session"]

    import docker
    client = docker.from_env()

    try:
        container = client.containers.get(container_name)
    except Exception:
        await websocket.send_json({"error": "Container not found"})
        await websocket.close()
        return

    # Use docker exec with interactive PTY to attach to tmux
    try:
        exec_handle = client.api.exec_create(
            container.id,
            ["tmux", "attach-session", "-t", tmux_session],
            stdin=True,
            tty=True,
            stdout=True,
            stderr=True,
        )
        sock = client.api.exec_start(exec_handle["Id"], socket=True, tty=True)
        raw_sock = sock._sock  # underlying socket

        async def read_from_container():
            """Read output from container and send to WebSocket."""
            loop = asyncio.get_event_loop()
            try:
                while True:
                    data = await loop.run_in_executor(None, lambda: raw_sock.recv(4096))
                    if not data:
                        break
                    await websocket.send_bytes(data)
            except Exception:
                pass

        async def write_to_container():
            """Read from WebSocket and write to container."""
            try:
                while True:
                    data = await websocket.receive()
                    if "text" in data:
                        raw_sock.sendall(data["text"].encode())
                    elif "bytes" in data:
                        raw_sock.sendall(data["bytes"])
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        # Run both tasks concurrently
        done, pending = await asyncio.wait(
            [asyncio.create_task(read_from_container()), asyncio.create_task(write_to_container())],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()

    except Exception as e:
        await websocket.send_json({"error": str(e)})
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass
