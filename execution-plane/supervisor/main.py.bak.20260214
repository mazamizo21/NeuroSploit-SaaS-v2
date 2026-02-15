#!/usr/bin/env python3
"""
TazoSploit Supervisor Service

Phase 1:
- Subscribe to Redis job output stream
- Emit structured events (iteration, command, warnings)
- Maintain lightweight heuristics for stalling / noop loops / repeated commands
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import time
import shlex
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, Optional

import httpx
import redis.asyncio as redis
import structlog
import docker

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except Exception:
    AIOHTTP_AVAILABLE = False

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

EVENT_LIST_MAX = int(os.getenv("SUPERVISOR_EVENT_LIST_MAX", "1000"))
EVENT_TTL_SECONDS = int(os.getenv("SUPERVISOR_EVENT_TTL_SECONDS", "86400"))

ALERT_STALL_SECONDS = int(os.getenv("SUPERVISOR_ALERT_STALL_SECONDS", "300"))
ALERT_NOOP_THRESHOLD = int(os.getenv("SUPERVISOR_ALERT_NOOP_THRESHOLD", "3"))
ALERT_REPEAT_THRESHOLD = int(os.getenv("SUPERVISOR_ALERT_REPEAT_THRESHOLD", "2"))
ALERT_COOLDOWN_SECONDS = int(os.getenv("SUPERVISOR_ALERT_COOLDOWN_SECONDS", "120"))
FINDINGS_STALL_SECONDS = int(os.getenv("SUPERVISOR_FINDINGS_STALL_SECONDS", "900"))

STATS_POLL_SECONDS = int(os.getenv("SUPERVISOR_STATS_POLL_SECONDS", "20"))
ACTIVE_WINDOW_SECONDS = int(os.getenv("SUPERVISOR_ACTIVE_WINDOW_SECONDS", "3600"))

SCAN_LOOP_WINDOW = int(os.getenv("SUPERVISOR_SCAN_LOOP_WINDOW", "20"))
SCAN_LOOP_ENUM_RATIO = float(os.getenv("SUPERVISOR_SCAN_LOOP_ENUM_RATIO", "0.7"))
SCAN_LOOP_MIN_COMMANDS = int(os.getenv("SUPERVISOR_SCAN_LOOP_MIN_COMMANDS", "12"))
SCAN_LOOP_EXPLOIT_GRACE_SECONDS = int(os.getenv("SUPERVISOR_SCAN_LOOP_EXPLOIT_GRACE_SECONDS", "180"))

HEALTH_PORT = int(os.getenv("SUPERVISOR_HEALTH_PORT", "9012"))

SUPERVISOR_LLM_MODE = os.getenv("SUPERVISOR_LLM_MODE", "stub").lower()  # disabled|stub|live
SUPERVISOR_LLM_PROVIDER = os.getenv("SUPERVISOR_LLM_PROVIDER", "anthropic").lower()
SUPERVISOR_LLM_API_BASE = os.getenv("SUPERVISOR_LLM_API_BASE", "https://api.anthropic.com")
SUPERVISOR_LLM_API_KEY = os.getenv("SUPERVISOR_LLM_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
SUPERVISOR_ANTHROPIC_VERSION = os.getenv("SUPERVISOR_ANTHROPIC_VERSION", "2023-06-01")
SUPERVISOR_TRIAGE_MODEL = os.getenv("SUPERVISOR_TRIAGE_MODEL", os.getenv("LLM_MODEL", "")).strip()
SUPERVISOR_ESCALATION_MODEL = os.getenv("SUPERVISOR_ESCALATION_MODEL", "").strip()
# Supervisor LLM calls can be slow (especially higher-end models). Default to a
# more realistic timeout to avoid "audit_failed" on healthy but slow responses.
SUPERVISOR_LLM_TIMEOUT_SECONDS = int(os.getenv("SUPERVISOR_LLM_TIMEOUT_SECONDS", "90"))
SUPERVISOR_LLM_MAX_TOKENS = int(os.getenv("SUPERVISOR_LLM_MAX_TOKENS", "800"))
SUPERVISOR_LLM_PROXY_TOKEN = os.getenv("SUPERVISOR_LLM_PROXY_TOKEN", "").strip()
if not SUPERVISOR_LLM_PROXY_TOKEN:
    SUPERVISOR_LLM_PROXY_TOKEN = os.getenv("LLM_PROXY_TOKEN", "").strip()
SUPERVISOR_LLM_PROVIDER_OVERRIDE = os.getenv("SUPERVISOR_LLM_PROVIDER_OVERRIDE", "").strip()

SUPERVISOR_AUDIT_ALERT_TYPES = set(
    t.strip()
    for t in os.getenv(
        "SUPERVISOR_AUDIT_ALERT_TYPES",
        "stalled,noop_loop,repeated_command,no_new_findings,stalling,scan_loop",
    ).split(",")
    if t.strip()
)
SUPERVISOR_AUDIT_MAX_PER_JOB = int(os.getenv("SUPERVISOR_AUDIT_MAX_PER_JOB", "10"))
SUPERVISOR_AUDIT_COOLDOWN_SECONDS = int(os.getenv("SUPERVISOR_AUDIT_COOLDOWN_SECONDS", "120"))

SUPERVISOR_ACTIONS_ENABLED = os.getenv("SUPERVISOR_ACTIONS_ENABLED", "true").lower() in ("1", "true", "yes")
SUPERVISOR_ACTIONS_DRY_RUN = os.getenv("SUPERVISOR_ACTIONS_DRY_RUN", "false").lower() in ("1", "true", "yes")
SUPERVISOR_ACTION_COOLDOWN_SECONDS = int(os.getenv("SUPERVISOR_ACTION_COOLDOWN_SECONDS", "120"))
SUPERVISOR_ACTION_MAX_PER_JOB = int(os.getenv("SUPERVISOR_ACTION_MAX_PER_JOB", "10"))
SUPERVISOR_HINT_PATH_TEMPLATE = os.getenv(
    "SUPERVISOR_HINT_PATH_TEMPLATE",
    "/pentest/output/{job_id}/supervisor_hints.jsonl",
)
SUPERVISOR_ENABLED_CACHE_SECONDS = int(os.getenv("SUPERVISOR_ENABLED_CACHE_SECONDS", "5"))
SUPERVISOR_ENABLED_DEFAULT = os.getenv("SUPERVISOR_ENABLED_DEFAULT", "true").lower() in ("1", "true", "yes")

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

logging.basicConfig(level=LOG_LEVEL)
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()

# ----------------------------------------------------------------------------
# Parsing helpers
# ----------------------------------------------------------------------------

LOG_LINE_RE = re.compile(r"^\[(?P<ts>[^\]]+)\] \[(?P<level>[A-Z]+)\] (?P<msg>.*)$")
ITERATION_RE = re.compile(r"^=== Iteration (?P<current>\d+)/(?P<total>\d+) ===$")
EXEC_RE = re.compile(r"^Executing \[(?P<exec_type>[^\]]+)\]: (?P<cmd>.+)$")

NOOP_COMMANDS = [':', 'sleep', 'wait', 'true', 'date', 'id', 'pwd', 'ls -la /pentest']
STALL_ECHO_PATTERNS = ['ready', 'waiting', 'standing by', 'idle', 'awaiting', 'done', 'complete', 'status']

ENUM_COMMAND_MARKERS = [
    "nmap", "masscan", "gobuster", "dirb", "dirsearch", "ffuf", "nikto",
    "whatweb", "nuclei", "amass", "subfinder", "assetfinder", "curl ",
    "dig ", "nslookup", "host ", "dnsrecon", "dnsenum", "whois",
    "nc -v", "nc -z", "telnet ",
]
EXPLOIT_COMMAND_MARKERS = [
    "sqlmap", "commix", "msfconsole", "searchsploit", "metasploit",
    "hydra", "medusa", "patator", "john", "hashcat", "crackmapexec",
    "pg_dump", "mysqldump", "reverse shell", "shell.php", "nc -e", "bash -i",
]
INJECTION_MARKERS = ["' or", "or 1=1", "union", "sleep(", "benchmark(", "--", "/*", "*/", "%27", "%3d"]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_int(value: Optional[str], default: int = 0) -> int:
    try:
        return int(value) if value is not None else default
    except Exception:
        return default


def _normalize_cmd(cmd: str) -> str:
    return " ".join((cmd or "").strip().split()).lower()


def _is_noop_command(cmd: str) -> bool:
    cmd_lower = _normalize_cmd(cmd)
    if not cmd_lower:
        return False
    for noop in NOOP_COMMANDS:
        if cmd_lower == noop or cmd_lower.startswith(noop + " "):
            return True
    if cmd_lower.startswith("echo") and any(pat in cmd_lower for pat in STALL_ECHO_PATTERNS):
        return True
    if cmd_lower.startswith("cat /pentest/output/"):
        return True
    return False


def _classify_cmd_intent(cmd: str) -> str:
    """Return exploit|enum|other based on simple heuristics."""
    cmd_lower = _normalize_cmd(cmd)
    if not cmd_lower:
        return "other"

    if "curl " in cmd_lower:
        # Treat curl with injection/upload markers as exploit.
        if any(m in cmd_lower for m in INJECTION_MARKERS) or "-f " in cmd_lower or "multipart/form-data" in cmd_lower:
            return "exploit"
        return "enum"

    if any(m in cmd_lower for m in EXPLOIT_COMMAND_MARKERS):
        return "exploit"
    if any(m in cmd_lower for m in ENUM_COMMAND_MARKERS):
        return "enum"
    return "other"


def _parse_log_line(line: str) -> Dict[str, Optional[str]]:
    m = LOG_LINE_RE.match(line)
    if not m:
        return {"ts": None, "level": None, "msg": line}
    return {"ts": m.group("ts"), "level": m.group("level"), "msg": m.group("msg")}


# ----------------------------------------------------------------------------
# State
# ----------------------------------------------------------------------------

@dataclass
class JobState:
    job_status: str = "unknown"
    last_status_ts: float = 0
    last_output_ts: float = 0
    last_iteration_ts: float = 0
    last_command_ts: float = 0
    last_progress_ts: float = 0
    last_findings_total: int = 0
    last_findings_ts: float = 0
    current_iteration: int = 0
    max_iterations: int = 0
    recent_commands: Deque[str] = field(default_factory=lambda: deque(maxlen=5))
    recent_cmd_classes: Deque[str] = field(default_factory=lambda: deque(maxlen=SCAN_LOOP_WINDOW))
    last_exploit_ts: float = 0
    noop_count: int = 0
    noop_since_ts: float = 0
    last_alert_ts: Dict[str, float] = field(default_factory=dict)
    audit_count: int = 0
    last_audit_ts: float = 0
    action_count: int = 0
    last_action_ts: float = 0


# ----------------------------------------------------------------------------
# Supervisor
# ----------------------------------------------------------------------------

class Supervisor:
    def __init__(self) -> None:
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        self.states: Dict[str, JobState] = {}
        self._stop_event = asyncio.Event()
        self._health_runner: Optional[web.AppRunner] = None
        if SUPERVISOR_ACTIONS_ENABLED:
            try:
                self.docker_client = docker.from_env()
            except Exception:
                self.docker_client = None
                logger.warn("docker_client_unavailable")
        else:
            self.docker_client = None
        self._enabled_cache_value = SUPERVISOR_ENABLED_DEFAULT
        self._enabled_cache_ts = 0.0
        self._provider_cache_value: Optional[str] = SUPERVISOR_LLM_PROVIDER_OVERRIDE or None
        self._provider_cache_ts = 0.0
        # Per-job caches: {job_id: (value, timestamp)}
        self._job_enabled_cache: Dict[str, tuple] = {}
        self._job_provider_cache: Dict[str, tuple] = {}

    def _get_state(self, job_id: str) -> JobState:
        if job_id not in self.states:
            self.states[job_id] = JobState()
        return self.states[job_id]

    async def start(self) -> None:
        logger.info("supervisor_started")
        await self._start_health_server()

        tasks = [
            asyncio.create_task(self._listen_output()),
            asyncio.create_task(self._listen_status()),
            asyncio.create_task(self._poll_live_stats()),
            asyncio.create_task(self._alert_sweeper()),
        ]

        await self._stop_event.wait()

        for task in tasks:
            task.cancel()
        await self._stop_health_server()
        try:
            await self.redis.close()
        except Exception:
            pass

    async def stop(self) -> None:
        self._stop_event.set()

    async def _start_health_server(self) -> None:
        if not AIOHTTP_AVAILABLE or HEALTH_PORT <= 0:
            return

        async def health(_request: web.Request) -> web.Response:
            payload = {
                "status": "ok",
                "time": _utc_now_iso(),
                "jobs_tracking": len(self.states),
            }
            return web.json_response(payload)

        app = web.Application()
        app.add_routes([web.get("/health", health)])
        self._health_runner = web.AppRunner(app)
        await self._health_runner.setup()
        site = web.TCPSite(self._health_runner, "0.0.0.0", HEALTH_PORT)
        await site.start()
        logger.info("health_server_started", port=HEALTH_PORT)

    async def _stop_health_server(self) -> None:
        if self._health_runner:
            await self._health_runner.cleanup()
            self._health_runner = None

    async def _listen_output(self) -> None:
        while not self._stop_event.is_set():
            try:
                pubsub = self.redis.pubsub()
                await pubsub.psubscribe("job:*:output")

                async for message in pubsub.listen():
                    if self._stop_event.is_set():
                        break
                    if message.get("type") != "pmessage":
                        continue

                    channel = message.get("channel")
                    if isinstance(channel, bytes):
                        channel = channel.decode()
                    if not isinstance(channel, str):
                        continue

                    parts = channel.split(":")
                    if len(parts) < 3:
                        continue
                    job_id = parts[1]

                    data = message.get("data")
                    if isinstance(data, bytes):
                        data = data.decode(errors="replace")

                    try:
                        payload = json.loads(data)
                    except Exception:
                        payload = {"line": str(data), "timestamp": _utc_now_iso()}

                    line = payload.get("line", "")
                    msg_ts = payload.get("timestamp") or _utc_now_iso()

                    await self._handle_output_line(job_id, line, msg_ts)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("output_listener_error", error=str(e))
                await asyncio.sleep(2)

    async def _listen_status(self) -> None:
        """Listen for job:*:status events so we can stop alerting on completed jobs."""
        terminal_statuses = {"completed", "failed", "cancelled", "canceled", "error"}
        while not self._stop_event.is_set():
            try:
                pubsub = self.redis.pubsub()
                await pubsub.psubscribe("job:*:status")

                async for message in pubsub.listen():
                    if self._stop_event.is_set():
                        break
                    if message.get("type") != "pmessage":
                        continue

                    channel = message.get("channel")
                    if isinstance(channel, bytes):
                        channel = channel.decode()
                    if not isinstance(channel, str):
                        continue

                    parts = channel.split(":")
                    if len(parts) < 3:
                        continue
                    job_id = parts[1]

                    data = message.get("data")
                    if isinstance(data, bytes):
                        data = data.decode(errors="replace")
                    try:
                        payload = json.loads(data)
                    except Exception:
                        payload = {"status": str(data), "timestamp": _utc_now_iso()}

                    status = str(payload.get("status") or "").strip().lower() or "unknown"
                    msg_ts = payload.get("timestamp") or _utc_now_iso()

                    state = self._get_state(job_id)
                    state.job_status = status
                    state.last_status_ts = time.time()

                    await self._emit_event(
                        job_id,
                        "job_status",
                        msg_ts,
                        "",
                        {"status": status},
                    )

                    if status in terminal_statuses:
                        # Stop tracking to avoid false "stalled" alerts after completion.
                        self.states.pop(job_id, None)
                        self._job_enabled_cache.pop(job_id, None)
                        self._job_provider_cache.pop(job_id, None)
                        logger.info("job_terminal_status", job_id=job_id, status=status)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("status_listener_error", error=str(e))
                await asyncio.sleep(2)

    async def _handle_output_line(self, job_id: str, line: str, msg_ts: str) -> None:
        now = time.time()
        state = self._get_state(job_id)
        state.last_output_ts = now

        parsed = _parse_log_line(line)
        level = parsed.get("level")
        msg = parsed.get("msg") or ""

        # Iteration event
        iter_match = ITERATION_RE.match(msg)
        if iter_match:
            current = _safe_int(iter_match.group("current"))
            total = _safe_int(iter_match.group("total"))
            state.current_iteration = current
            state.max_iterations = total
            state.last_iteration_ts = now
            state.last_progress_ts = now

            await self._emit_event(
                job_id,
                "iteration",
                msg_ts,
                line,
                {
                    "current": current,
                    "total": total,
                },
            )
            return

        # Command execution event
        exec_match = EXEC_RE.match(msg)
        if exec_match:
            exec_type = exec_match.group("exec_type")
            cmd = exec_match.group("cmd")
            state.last_command_ts = now
            state.last_progress_ts = now

            normalized_cmd = _normalize_cmd(cmd)
            if normalized_cmd:
                state.recent_commands.append(normalized_cmd)

            await self._emit_event(
                job_id,
                "command",
                msg_ts,
                line,
                {
                    "exec_type": exec_type,
                    "command": cmd,
                },
            )

            await self._maybe_emit_noop_alert(job_id, state, cmd, now)
            await self._maybe_emit_repeat_alert(job_id, state, normalized_cmd, now)
            await self._maybe_emit_scan_loop_alert(job_id, state, cmd, now)
            return

        # Stalling signal from agent
        if "STALLING DETECTED" in msg:
            await self._emit_event(
                job_id,
                "stalling",
                msg_ts,
                line,
                {"message": msg},
            )
            return

        # Warnings / errors
        if level in {"WARN", "ERROR"}:
            await self._emit_event(
                job_id,
                "log",
                msg_ts,
                line,
                {"level": level, "message": msg},
            )

    async def _emit_event(self, job_id: str, event_type: str, msg_ts: str, line: str, data: Dict) -> None:
        payload = {
            "job_id": job_id,
            "event_type": event_type,
            "timestamp": msg_ts,
            "line": line,
            "data": data,
        }

        channel = f"job:{job_id}:supervisor_events"
        list_key = f"job:{job_id}:supervisor_log"

        try:
            await self.redis.publish(channel, json.dumps(payload))
            await self.redis.rpush(list_key, json.dumps(payload))
            await self.redis.ltrim(list_key, -EVENT_LIST_MAX, -1)
            await self.redis.expire(list_key, EVENT_TTL_SECONDS)
        except Exception as e:
            logger.warn("emit_event_failed", error=str(e), job_id=job_id, event_type=event_type)

    async def _emit_alert(self, job_id: str, alert_type: str, data: Dict) -> None:
        await self._emit_event(
            job_id,
            "alert",
            _utc_now_iso(),
            "",
            {"alert_type": alert_type, **data},
        )
        state = self._get_state(job_id)
        await self._schedule_audit(job_id, state, alert_type, data)

    async def _schedule_audit(self, job_id: str, state: JobState, alert_type: str, data: Dict) -> None:
        if not await self._is_supervisor_enabled(job_id):
            return
        if not self._should_audit(state, alert_type):
            return
        state.audit_count += 1
        state.last_audit_ts = time.time()
        logger.info("audit_scheduled", job_id=job_id, alert_type=alert_type)
        asyncio.create_task(self._run_audit(job_id, alert_type, data, state))

    def _should_audit(self, state: JobState, alert_type: str) -> bool:
        if SUPERVISOR_LLM_MODE == "disabled":
            return False
        if alert_type not in SUPERVISOR_AUDIT_ALERT_TYPES:
            return False
        if state.audit_count >= SUPERVISOR_AUDIT_MAX_PER_JOB:
            # Fix #12: Don't completely stop — allow one more audit every 5 minutes
            # even after hitting the cap, so supervisor never fully disengages
            if state.last_audit_ts and time.time() - state.last_audit_ts < 300:
                return False
        if state.last_audit_ts and time.time() - state.last_audit_ts < SUPERVISOR_AUDIT_COOLDOWN_SECONDS:
            return False
        return True

    async def _maybe_emit_noop_alert(self, job_id: str, state: JobState, cmd: str, now: float) -> None:
        if not _is_noop_command(cmd):
            state.noop_count = 0
            state.noop_since_ts = 0
            return

        if state.noop_since_ts == 0:
            state.noop_since_ts = now
            state.noop_count = 1
        else:
            # Reset window if too much time passed
            if now - state.noop_since_ts > ALERT_STALL_SECONDS:
                state.noop_since_ts = now
                state.noop_count = 1
            else:
                state.noop_count += 1

        if state.noop_count >= ALERT_NOOP_THRESHOLD:
            if self._cooldown_ok(state, "noop", now):
                await self._emit_alert(
                    job_id,
                    "noop_loop",
                    {
                        "count": state.noop_count,
                        "command": cmd,
                    },
                )

    async def _maybe_emit_repeat_alert(self, job_id: str, state: JobState, cmd: str, now: float) -> None:
        if not cmd:
            return
        repeats = list(state.recent_commands).count(cmd)
        if repeats >= ALERT_REPEAT_THRESHOLD and self._cooldown_ok(state, "repeat", now):
            await self._emit_alert(
                job_id,
                "repeated_command",
                {
                    "command": cmd,
                    "count": repeats,
                    "recent": list(state.recent_commands),
                },
            )

    async def _maybe_emit_scan_loop_alert(self, job_id: str, state: JobState, cmd: str, now: float) -> None:
        """Detect enumeration-heavy loops with no exploitation progress."""
        if not cmd:
            return
        intent = _classify_cmd_intent(cmd)
        if intent:
            state.recent_cmd_classes.append(intent)
            if intent == "exploit":
                state.last_exploit_ts = now

        window = list(state.recent_cmd_classes)
        if len(window) < SCAN_LOOP_MIN_COMMANDS:
            return

        enum_ratio = window.count("enum") / max(len(window), 1)
        if enum_ratio < SCAN_LOOP_ENUM_RATIO:
            return

        if state.last_exploit_ts and now - state.last_exploit_ts < SCAN_LOOP_EXPLOIT_GRACE_SECONDS:
            return

        if self._cooldown_ok(state, "scan_loop", now):
            await self._emit_alert(
                job_id,
                "scan_loop",
                {
                    "enum_ratio": round(enum_ratio, 2),
                    "window": len(window),
                    "recent": window[-10:],
                },
            )

    def _cooldown_ok(self, state: JobState, key: str, now: float) -> bool:
        last = state.last_alert_ts.get(key, 0)
        if now - last >= ALERT_COOLDOWN_SECONDS:
            state.last_alert_ts[key] = now
            return True
        return False

    async def _is_supervisor_enabled(self, job_id: Optional[str] = None) -> bool:
        now = time.time()
        # Check per-job override first
        if job_id:
            cached = self._job_enabled_cache.get(job_id)
            if cached and now - cached[1] < SUPERVISOR_ENABLED_CACHE_SECONDS:
                return cached[0]
            try:
                val = await self.redis.get(f"job:{job_id}:supervisor_enabled")
                if val is not None:
                    enabled = str(val).strip().lower() in ("1", "true", "yes", "on")
                    self._job_enabled_cache[job_id] = (enabled, now)
                    return enabled
            except Exception:
                pass
        # Fall back to global setting
        if now - self._enabled_cache_ts < SUPERVISOR_ENABLED_CACHE_SECONDS:
            return self._enabled_cache_value
        enabled = SUPERVISOR_ENABLED_DEFAULT
        try:
            val = await self.redis.get("supervisor:enabled")
            if val is not None:
                enabled = str(val).strip().lower() in ("1", "true", "yes", "on")
        except Exception:
            pass
        self._enabled_cache_value = enabled
        self._enabled_cache_ts = now
        return enabled

    async def _get_supervisor_provider_override(self, job_id: Optional[str] = None) -> Optional[str]:
        """Read supervisor LLM provider from Redis (cached ~5s), fall back to env var."""
        now = time.time()
        # Check per-job override first
        if job_id:
            cached = self._job_provider_cache.get(job_id)
            if cached and now - cached[1] < SUPERVISOR_ENABLED_CACHE_SECONDS:
                return cached[0]
            try:
                val = await self.redis.get(f"job:{job_id}:supervisor_provider")
                if val and str(val).strip():
                    provider = str(val).strip()
                    self._job_provider_cache[job_id] = (provider, now)
                    return provider
            except Exception:
                pass
        # Fall back to global setting
        if now - self._provider_cache_ts < SUPERVISOR_ENABLED_CACHE_SECONDS:
            return self._provider_cache_value
        provider = SUPERVISOR_LLM_PROVIDER_OVERRIDE or None
        try:
            val = await self.redis.get("supervisor:provider")
            if val and str(val).strip():
                provider = str(val).strip()
        except Exception:
            pass
        self._provider_cache_value = provider
        self._provider_cache_ts = now
        return provider

    async def _run_audit(self, job_id: str, alert_type: str, data: Dict, state: JobState) -> None:
        try:
            context = await self._build_audit_context(job_id, state)
            try:
                decision = await self._audit_decision(job_id, alert_type, data, context)
            except Exception as e:
                # If the LLM proxy is rate limited or transiently failing, fall back to stub behavior
                # instead of marking the audit as failed. This keeps "watch and fix" working even
                # under provider throttling.
                status = None
                try:
                    import httpx  # type: ignore
                    if isinstance(e, httpx.HTTPStatusError) and e.response is not None:
                        status = e.response.status_code
                except Exception:
                    status = None
                if status in (429, 500, 502, 503, 504):
                    logger.warn("audit_llm_unavailable_fallback_stub", job_id=job_id, alert_type=alert_type, status=status)
                    decision = self._stub_audit(alert_type, data, context)
                    decision["tier"] = "stub"
                    decision["note"] = f"llm_unavailable_{status}"
                else:
                    raise
            if not decision:
                return
            logger.info(
                "audit_decision",
                job_id=job_id,
                alert_type=alert_type,
                action=decision.get("action"),
                severity=decision.get("severity"),
                model=decision.get("model"),
                tier=decision.get("tier"),
            )
            await self._emit_event(
                job_id,
                "audit",
                _utc_now_iso(),
                "",
                {
                    "alert_type": alert_type,
                    "decision": decision,
                    "context": context,
                },
            )
            await self._maybe_execute_action(job_id, state, decision)
        except Exception as e:
            logger.warn("audit_failed", job_id=job_id, alert_type=alert_type, error=str(e))

    async def _build_audit_context(self, job_id: str, state: JobState) -> Dict:
        list_key = f"job:{job_id}:supervisor_log"
        try:
            raw_events = await self.redis.lrange(list_key, -10, -1)
        except Exception:
            raw_events = []
        events = []
        for item in raw_events:
            try:
                events.append(json.loads(item))
            except Exception:
                continue

        stats_key = f"job:{job_id}:live_stats"
        try:
            stats = await self.redis.hgetall(stats_key)
        except Exception:
            stats = {}

        context = {
            "recent_commands": list(state.recent_commands),
            "current_iteration": state.current_iteration,
            "max_iterations": state.max_iterations,
            "last_progress_seconds": int(time.time() - (state.last_progress_ts or state.last_output_ts or time.time())),
            "live_stats": stats,
            "recent_events": events,
        }
        return context

    async def _audit_decision(self, job_id: str, alert_type: str, data: Dict, context: Dict) -> Dict:
        if SUPERVISOR_LLM_MODE == "stub":
            decision = self._stub_audit(alert_type, data, context)
            decision["tier"] = "stub"
            return decision

        if SUPERVISOR_LLM_MODE != "live":
            return {}

        provider = SUPERVISOR_LLM_PROVIDER
        if provider not in {"internal_proxy", "proxy", "internal"}:
            if not SUPERVISOR_LLM_API_KEY or not SUPERVISOR_TRIAGE_MODEL:
                logger.warn("audit_missing_llm_config", job_id=job_id)
                decision = self._stub_audit(alert_type, data, context)
                decision["tier"] = "stub"
                decision["note"] = "Missing LLM config; fell back to stub"
                return decision

        system_prompt = (
            "You are a supervising safety/quality agent for an autonomous penetration testing worker. "
            "You see alerts about stalling, repeated commands, scan/enumeration loops, or lack of progress. "
            "Return a STRICT JSON object with keys: action, severity, rationale, hint, next_strategy, confidence. "
            "Allowed actions: ignore, hint, retry, reset, stop. "
            "Do not include any extra text outside JSON."
        )

        user_prompt = json.dumps(
            {
                "job_id": job_id,
                "alert_type": alert_type,
                "alert_data": data,
                "context": context,
            },
            indent=2,
        )

        decision = await self._call_llm(SUPERVISOR_TRIAGE_MODEL, system_prompt, user_prompt, job_id)
        decision = self._normalize_decision(decision, model=SUPERVISOR_TRIAGE_MODEL, tier="triage")

        if SUPERVISOR_ESCALATION_MODEL:
            if decision.get("severity") in {"high", "critical"} or decision.get("action") in {"reset", "stop"}:
                escalation = await self._call_llm(SUPERVISOR_ESCALATION_MODEL, system_prompt, user_prompt, job_id)
                escalation = self._normalize_decision(
                    escalation, model=SUPERVISOR_ESCALATION_MODEL, tier="escalation"
                )
                if escalation:
                    decision = escalation

        return decision

    async def _call_llm(self, model: str, system_prompt: str, user_prompt: str, job_id: Optional[str] = None) -> Dict:
        provider = SUPERVISOR_LLM_PROVIDER

        if provider in {"internal_proxy", "proxy", "internal"}:
            if not SUPERVISOR_LLM_PROXY_TOKEN:
                logger.warn("missing_proxy_token")
                return self._stub_audit("missing_proxy_token", {}, {})
            if not SUPERVISOR_LLM_API_BASE:
                logger.warn("missing_proxy_base")
                return self._stub_audit("missing_proxy_base", {}, {})

            headers = {
                "X-LLM-Proxy-Token": SUPERVISOR_LLM_PROXY_TOKEN,
                "Content-Type": "application/json",
            }
            payload = {
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": SUPERVISOR_LLM_MAX_TOKENS,
                "temperature": 0,
            }
            # Dynamic provider override: per-job > global Redis > env var
            provider_override = await self._get_supervisor_provider_override(job_id)
            if provider_override:
                payload["provider_override"] = provider_override

            async with httpx.AsyncClient(timeout=SUPERVISOR_LLM_TIMEOUT_SECONDS) as client:
                resp = await client.post(SUPERVISOR_LLM_API_BASE, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()

            text = data.get("content", "") if isinstance(data, dict) else ""
            parsed = self._parse_llm_json(text)
            if isinstance(parsed, dict):
                if not parsed.get("model"):
                    provider_id = data.get("provider") if isinstance(data, dict) else ""
                    model_id = data.get("model") if isinstance(data, dict) else model
                    parsed["model"] = f"{provider_id}/{model_id}".strip("/")
            return parsed

        if provider != "anthropic":
            logger.warn("unsupported_llm_provider", provider=provider)
            return self._stub_audit("unsupported_provider", {}, {})

        headers = {
            "x-api-key": SUPERVISOR_LLM_API_KEY,
            "anthropic-version": SUPERVISOR_ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": SUPERVISOR_LLM_MAX_TOKENS,
            "temperature": 0,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }

        async with httpx.AsyncClient(timeout=SUPERVISOR_LLM_TIMEOUT_SECONDS) as client:
            resp = await client.post(f"{SUPERVISOR_LLM_API_BASE}/v1/messages", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

        content = data.get("content", [])
        text = ""
        if isinstance(content, list) and content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
        elif isinstance(content, str):
            text = content

        parsed = self._parse_llm_json(text)
        if isinstance(parsed, dict) and not parsed.get("model"):
            parsed["model"] = model
        return parsed

    def _parse_llm_json(self, text: str) -> Dict:
        if not text:
            return {}
        text = text.strip()
        try:
            return json.loads(text)
        except Exception:
            # Try to extract a JSON object from text
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except Exception:
                    return {}
        return {}

    def _normalize_decision(self, decision: Dict, model: str, tier: str) -> Dict:
        if not isinstance(decision, dict):
            return {}
        note = decision.get("note", "")
        if not decision.get("action") and not note:
            note = "llm_parse_failed"
        normalized = {
            "action": decision.get("action", "hint"),
            "severity": decision.get("severity", "medium"),
            "rationale": decision.get("rationale", ""),
            "hint": decision.get("hint", ""),
            "next_strategy": decision.get("next_strategy", ""),
            "confidence": decision.get("confidence", 0.5),
            "model": decision.get("model") or model,
            "tier": tier,
            "note": note,
        }
        return normalized

    def _stub_audit(self, alert_type: str, data: Dict, context: Dict) -> Dict:
        action = "hint"
        severity = "low"
        hint = "Change approach and avoid repeating noop commands."
        next_strategy = "Pick a different tool or target path; validate with evidence."

        if alert_type in {"stalled", "no_new_findings"}:
            action = "retry"
            severity = "medium"
            hint = "Progress stalled. Try a different recon or exploit path."
            next_strategy = "Switch tools; narrow scope; validate at least one vuln."
        elif alert_type in {"noop_loop", "repeated_command"}:
            action = "hint"
            severity = "medium"
            hint = "Stop repeating the same command. Try a distinct technique."
            next_strategy = "Choose an alternate tool or vector and proceed."
        elif alert_type == "stalling":
            action = "hint"
            severity = "medium"
            hint = "Agent claims done but has no evidence. Continue testing."
            next_strategy = "Validate findings with concrete proof."
        elif alert_type == "scan_loop":
            action = "hint"
            severity = "medium"
            hint = "Enumeration loop detected. Stop scanning and perform exploitation."
            next_strategy = "Run sqlmap --dump or attempt RCE/file upload; capture proof."

        return {
            "action": action,
            "severity": severity,
            "rationale": f"Stub decision for alert {alert_type}",
            "hint": hint,
            "next_strategy": next_strategy,
            "confidence": 0.5,
            "model": "stub",
        }

    def _escalation_ladder_action(self, state: JobState, decision: Dict) -> str:
        """Fix #5: Escalation ladder — hint(x2) → force_pivot → inject_command → early_terminate.
        
        Returns the escalated action string based on how many actions have been taken.
        """
        base_action = decision.get("action", "hint").lower()
        hint_count = state.action_count  # How many actions already taken

        # If the LLM or stub already said stop, respect it
        if base_action == "stop":
            return "early_terminate"

        # Escalation ladder based on accumulated action count
        if hint_count < 2:
            return "hint"
        elif hint_count < 4:
            return "force_pivot"
        elif hint_count < 6:
            return "inject_command"
        else:
            return "early_terminate"

    async def _maybe_execute_action(self, job_id: str, state: JobState, decision: Dict) -> None:
        if not SUPERVISOR_ACTIONS_ENABLED:
            return
        if not await self._is_supervisor_enabled(job_id):
            return
        if not decision:
            return
        if state.action_count >= SUPERVISOR_ACTION_MAX_PER_JOB:
            return
        if state.last_action_ts and time.time() - state.last_action_ts < SUPERVISOR_ACTION_COOLDOWN_SECONDS:
            return

        # Fix #5: Apply escalation ladder
        action = self._escalation_ladder_action(state, decision)
        logger.info("escalation_ladder", job_id=job_id, raw_action=decision.get("action"), escalated_action=action, action_count=state.action_count)

        state.action_count += 1
        state.last_action_ts = time.time()
        await self._execute_action(job_id, action, decision)

    async def _execute_action(self, job_id: str, action: str, decision: Dict) -> None:
        result = {"action": action, "success": False, "detail": ""}

        if SUPERVISOR_ACTIONS_DRY_RUN:
            result["success"] = True
            result["detail"] = "dry_run"
            await self._emit_event(job_id, "action", _utc_now_iso(), "", result)
            return

        if action in ("stop", "early_terminate"):
            try:
                await self.redis.publish(f"job:{job_id}:control", "CANCEL")
                result["success"] = True
                result["detail"] = f"cancel_sent (escalation: {action})"
            except Exception as e:
                result["detail"] = f"cancel_failed: {e}"
            # Also write the termination directive so the agent can log it
            try:
                directive = {
                    "id": f"{job_id}-{int(time.time()*1000)}",
                    "timestamp": _utc_now_iso(),
                    "action": "early_terminate",
                    "severity": "critical",
                    "message": self._build_hint_message(decision),
                    "rationale": decision.get("rationale", ""),
                    "model": decision.get("model", ""),
                }
                await self._write_hint_to_container(job_id, directive)
            except Exception:
                pass
            await self._emit_event(job_id, "action", _utc_now_iso(), "", result)
            return

        # hint / retry / reset / force_pivot / inject_command -> write supervisor directive into Kali container
        try:
            directive = {
                "id": f"{job_id}-{int(time.time()*1000)}",
                "timestamp": _utc_now_iso(),
                "action": action,
                "severity": decision.get("severity", "medium"),
                "message": self._build_hint_message(decision),
                "rationale": decision.get("rationale", ""),
                "model": decision.get("model", ""),
            }
            await self._write_hint_to_container(job_id, directive)
            result["success"] = True
            result["detail"] = f"{action}_written"
        except Exception as e:
            result["detail"] = f"{action}_failed: {e}"

        await self._emit_event(job_id, "action", _utc_now_iso(), "", result)

    def _build_hint_message(self, decision: Dict) -> str:
        hint = decision.get("hint", "") or ""
        next_strategy = decision.get("next_strategy", "") or ""
        if hint and next_strategy:
            return f"{hint}\n\nNext strategy: {next_strategy}"
        return hint or next_strategy or "Adjust approach and continue."

    async def _write_hint_to_container(self, job_id: str, directive: Dict) -> None:
        if not self.docker_client:
            raise RuntimeError("Docker client unavailable")

        container_id = await self.redis.get(f"job:{job_id}:kali_container")
        container_name = await self.redis.get(f"job:{job_id}:kali_container_name")
        target_id = container_id or container_name
        if not target_id:
            raise RuntimeError("Missing kali container mapping for job")

        hint_path = SUPERVISOR_HINT_PATH_TEMPLATE.format(job_id=job_id)
        hint_dir = os.path.dirname(hint_path)
        payload = json.dumps(directive, ensure_ascii=True)

        # Use a heredoc to avoid shell escaping issues
        heredoc = f"mkdir -p {shlex.quote(hint_dir)} && cat <<'EOF' >> {shlex.quote(hint_path)}\n{payload}\nEOF"
        container = self.docker_client.containers.get(target_id)
        exec_result = container.exec_run(cmd=["bash", "-lc", heredoc])
        if exec_result.exit_code != 0:
            raise RuntimeError(exec_result.output.decode(errors="replace"))

    async def _poll_live_stats(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(STATS_POLL_SECONDS)
                now = time.time()
                for job_id, state in list(self.states.items()):
                    if state.last_output_ts and now - state.last_output_ts > ACTIVE_WINDOW_SECONDS:
                        self.states.pop(job_id, None)
                        self._job_enabled_cache.pop(job_id, None)
                        self._job_provider_cache.pop(job_id, None)
                        continue

                    stats_key = f"job:{job_id}:live_stats"
                    stats = await self.redis.hgetall(stats_key)
                    if not stats:
                        continue

                    total_findings = _safe_int(stats.get("total_findings"), state.last_findings_total)
                    if total_findings > state.last_findings_total:
                        state.last_findings_total = total_findings
                        state.last_findings_ts = now
                        state.last_progress_ts = now
                        await self._emit_event(
                            job_id,
                            "finding_update",
                            _utc_now_iso(),
                            "",
                            {"total_findings": total_findings},
                        )

                    current_iter = _safe_int(stats.get("current_iteration"), state.current_iteration)
                    max_iter = _safe_int(stats.get("max_iterations"), state.max_iterations)
                    if current_iter and current_iter != state.current_iteration:
                        state.current_iteration = current_iter
                    if max_iter and max_iter != state.max_iterations:
                        state.max_iterations = max_iter
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("stats_poll_error", error=str(e))

    async def _alert_sweeper(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(10)
                now = time.time()
                for job_id, state in list(self.states.items()):
                    if state.last_output_ts and now - state.last_output_ts > ACTIVE_WINDOW_SECONDS:
                        self.states.pop(job_id, None)
                        self._job_enabled_cache.pop(job_id, None)
                        self._job_provider_cache.pop(job_id, None)
                        continue

                    last_progress = state.last_progress_ts or state.last_output_ts
                    if last_progress and now - last_progress > ALERT_STALL_SECONDS:
                        if self._cooldown_ok(state, "stall", now):
                            await self._emit_alert(
                                job_id,
                                "stalled",
                                {
                                    "seconds_since_progress": int(now - last_progress),
                                    "current_iteration": state.current_iteration,
                                    "max_iterations": state.max_iterations,
                                },
                            )

                    if state.last_findings_ts and now - state.last_findings_ts > FINDINGS_STALL_SECONDS:
                        if self._cooldown_ok(state, "findings", now):
                            await self._emit_alert(
                                job_id,
                                "no_new_findings",
                                {
                                    "seconds_since_findings": int(now - state.last_findings_ts),
                                    "total_findings": state.last_findings_total,
                                },
                            )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("alert_sweeper_error", error=str(e))


async def _run() -> None:
    supervisor = Supervisor()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(supervisor.stop()))
        except NotImplementedError:
            pass

    await supervisor.start()


if __name__ == "__main__":
    asyncio.run(_run())
