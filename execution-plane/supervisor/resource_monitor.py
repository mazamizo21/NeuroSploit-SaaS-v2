#!/usr/bin/env python3
"""
TazoSploit Supervisor – Resource Monitor

Monitors Docker container resource usage (primarily memory) for Kali executor
containers and triggers interventions before OOM kills happen.

Thresholds:
  - 70%: Log warning, start monitoring more frequently
  - 80%: Trigger context trim directive to agent
  - 90%: Send SAVE_AND_RESET directive (save findings, reset context)
  - 95%: Emergency — send CANCEL to prevent OOM crash

Integrates with the supervisor's Redis pub/sub and Docker API.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Coroutine, Dict, List, Optional, Any

import structlog

try:
    import docker
    import docker.errors
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Polling intervals (seconds)
RESOURCE_POLL_NORMAL = int(os.getenv("SUPERVISOR_RESOURCE_POLL_NORMAL", "30"))
RESOURCE_POLL_ELEVATED = int(os.getenv("SUPERVISOR_RESOURCE_POLL_ELEVATED", "10"))
RESOURCE_POLL_CRITICAL = int(os.getenv("SUPERVISOR_RESOURCE_POLL_CRITICAL", "5"))

# Memory thresholds (fraction of container memory limit)
MEM_THRESHOLD_WARN = float(os.getenv("SUPERVISOR_MEM_THRESHOLD_WARN", "0.70"))
MEM_THRESHOLD_TRIM = float(os.getenv("SUPERVISOR_MEM_THRESHOLD_TRIM", "0.80"))
MEM_THRESHOLD_RESET = float(os.getenv("SUPERVISOR_MEM_THRESHOLD_RESET", "0.90"))
MEM_THRESHOLD_EMERGENCY = float(os.getenv("SUPERVISOR_MEM_THRESHOLD_EMERGENCY", "0.95"))

# Cooldowns (seconds) between directives of the same type per container
RESOURCE_DIRECTIVE_COOLDOWN = int(os.getenv("SUPERVISOR_RESOURCE_DIRECTIVE_COOLDOWN", "120"))

# History for trending
MEMORY_HISTORY_SIZE = int(os.getenv("SUPERVISOR_MEMORY_HISTORY_SIZE", "60"))


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class MemorySnapshot:
    """A point-in-time memory reading for a container."""
    timestamp: float
    usage_bytes: int
    limit_bytes: int
    usage_fraction: float
    rss_bytes: int = 0
    cache_bytes: int = 0

    @property
    def usage_mb(self) -> float:
        return self.usage_bytes / (1024 * 1024)

    @property
    def limit_mb(self) -> float:
        return self.limit_bytes / (1024 * 1024)

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "usage_mb": round(self.usage_mb, 1),
            "limit_mb": round(self.limit_mb, 1),
            "usage_fraction": round(self.usage_fraction, 3),
            "rss_mb": round(self.rss_bytes / (1024 * 1024), 1),
            "cache_mb": round(self.cache_bytes / (1024 * 1024), 1),
        }


@dataclass
class ResourceAlert:
    """Alert generated when a resource threshold is crossed."""
    alert_type: str        # mem_warn | mem_trim | mem_reset | mem_emergency
    severity: str          # low | medium | high | critical
    message: str
    directive: str          # Action for the agent
    container_id: str
    job_id: str
    snapshot: MemorySnapshot
    trend: str = "stable"   # rising | stable | falling

    def to_dict(self) -> Dict:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "directive": self.directive,
            "container_id": self.container_id,
            "job_id": self.job_id,
            "snapshot": self.snapshot.to_dict(),
            "trend": self.trend,
        }


@dataclass
class ContainerState:
    """Tracked state for a single container."""
    container_id: str
    job_id: str
    history: List[MemorySnapshot] = field(default_factory=list)
    last_directive_ts: Dict[str, float] = field(default_factory=dict)  # directive_type → ts
    alert_level: str = "normal"  # normal | elevated | critical
    last_poll_ts: float = 0.0
    consecutive_failures: int = 0

    @property
    def poll_interval(self) -> float:
        if self.alert_level == "critical":
            return RESOURCE_POLL_CRITICAL
        elif self.alert_level == "elevated":
            return RESOURCE_POLL_ELEVATED
        return RESOURCE_POLL_NORMAL

    def add_snapshot(self, snap: MemorySnapshot) -> None:
        self.history.append(snap)
        if len(self.history) > MEMORY_HISTORY_SIZE:
            self.history = self.history[-MEMORY_HISTORY_SIZE:]

    def get_trend(self, lookback: int = 5) -> str:
        """Analyze memory trend over recent snapshots."""
        if len(self.history) < 3:
            return "stable"
        recent = self.history[-lookback:]
        if len(recent) < 2:
            return "stable"
        # Compare first third vs last third
        split = max(len(recent) // 3, 1)
        early_avg = sum(s.usage_fraction for s in recent[:split]) / split
        late_avg = sum(s.usage_fraction for s in recent[-split:]) / split
        diff = late_avg - early_avg
        if diff > 0.05:
            return "rising"
        elif diff < -0.05:
            return "falling"
        return "stable"

    def can_send_directive(self, directive_type: str) -> bool:
        last = self.last_directive_ts.get(directive_type, 0)
        return time.time() - last >= RESOURCE_DIRECTIVE_COOLDOWN

    def mark_directive_sent(self, directive_type: str) -> None:
        self.last_directive_ts[directive_type] = time.time()


# ---------------------------------------------------------------------------
# Resource Monitor
# ---------------------------------------------------------------------------

# Callback type: async fn(job_id, alert) -> None
AlertCallback = Callable[[str, ResourceAlert], Coroutine[Any, Any, None]]


class ResourceMonitor:
    """
    Monitors Docker containers for memory/resource issues.

    Usage:
        monitor = ResourceMonitor(on_alert=my_callback)
        # Register containers to monitor
        monitor.track_container(job_id, container_id)
        # Start the monitoring loop
        await monitor.run(stop_event)
    """

    def __init__(
        self,
        on_alert: Optional[AlertCallback] = None,
        docker_client: Optional[Any] = None,
    ) -> None:
        self._containers: Dict[str, ContainerState] = {}  # container_id → state
        self._job_to_container: Dict[str, str] = {}  # job_id → container_id
        self._on_alert = on_alert

        if docker_client is not None:
            self._docker = docker_client
        elif DOCKER_AVAILABLE:
            try:
                self._docker = docker.from_env()
            except Exception:
                self._docker = None
                logger.warn("resource_monitor_docker_unavailable")
        else:
            self._docker = None

    def track_container(self, job_id: str, container_id: str) -> None:
        """Start monitoring a container for a job."""
        if container_id in self._containers:
            return
        self._containers[container_id] = ContainerState(
            container_id=container_id,
            job_id=job_id,
        )
        self._job_to_container[job_id] = container_id
        logger.info("resource_monitor_tracking", job_id=job_id, container_id=container_id[:12])

    def untrack_container(self, container_id: str) -> None:
        """Stop monitoring a container."""
        state = self._containers.pop(container_id, None)
        if state:
            self._job_to_container.pop(state.job_id, None)
            logger.info("resource_monitor_untracked", container_id=container_id[:12])

    def untrack_job(self, job_id: str) -> None:
        """Stop monitoring by job ID."""
        cid = self._job_to_container.pop(job_id, None)
        if cid:
            self._containers.pop(cid, None)

    def get_snapshot(self, job_id: str) -> Optional[MemorySnapshot]:
        """Get the latest memory snapshot for a job (if tracked)."""
        cid = self._job_to_container.get(job_id)
        if not cid:
            return None
        state = self._containers.get(cid)
        if not state or not state.history:
            return None
        return state.history[-1]

    def get_memory_stats(self, job_id: str) -> Optional[Dict]:
        """Get detailed memory stats for a job, suitable for logging."""
        snap = self.get_snapshot(job_id)
        if not snap:
            return None
        cid = self._job_to_container.get(job_id)
        state = self._containers.get(cid) if cid else None
        result = snap.to_dict()
        if state:
            result["trend"] = state.get_trend()
            result["alert_level"] = state.alert_level
            result["snapshots_collected"] = len(state.history)
        return result

    async def run(self, stop_event: asyncio.Event) -> None:
        """Main monitoring loop. Runs until stop_event is set."""
        if not self._docker:
            logger.warn("resource_monitor_no_docker_skipping")
            return

        logger.info("resource_monitor_started")
        while not stop_event.is_set():
            try:
                now = time.time()
                for cid, state in list(self._containers.items()):
                    # Respect per-container polling interval
                    if now - state.last_poll_ts < state.poll_interval:
                        continue

                    state.last_poll_ts = now
                    try:
                        snapshot = await self._read_container_stats(cid, state)
                        if snapshot:
                            state.add_snapshot(snapshot)
                            state.consecutive_failures = 0
                            alerts = self._evaluate_thresholds(state, snapshot)
                            for alert in alerts:
                                await self._fire_alert(alert)
                    except docker.errors.NotFound:
                        logger.info("resource_monitor_container_gone", container_id=cid[:12])
                        self.untrack_container(cid)
                    except Exception as e:
                        state.consecutive_failures += 1
                        if state.consecutive_failures <= 3:
                            logger.warn("resource_monitor_read_failed",
                                        container_id=cid[:12], error=str(e),
                                        failures=state.consecutive_failures)
                        if state.consecutive_failures > 10:
                            logger.error("resource_monitor_giving_up", container_id=cid[:12])
                            self.untrack_container(cid)

                # Sleep for shortest needed interval
                min_interval = RESOURCE_POLL_NORMAL
                for state in self._containers.values():
                    min_interval = min(min_interval, state.poll_interval)
                await asyncio.sleep(min(min_interval, 5))

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("resource_monitor_loop_error", error=str(e))
                await asyncio.sleep(5)

        logger.info("resource_monitor_stopped")

    async def _read_container_stats(
        self, container_id: str, state: ContainerState
    ) -> Optional[MemorySnapshot]:
        """Read memory stats from Docker for a container. Uses one-shot stats API."""
        if not self._docker:
            return None

        # Run Docker stats call in a thread (it's blocking)
        loop = asyncio.get_event_loop()
        stats = await loop.run_in_executor(
            None,
            lambda: self._docker.containers.get(container_id).stats(stream=False),
        )

        if not stats:
            return None

        mem_stats = stats.get("memory_stats", {})
        usage = mem_stats.get("usage", 0)
        limit = mem_stats.get("limit", 0)

        # Some Docker versions report limit as host total RAM when no limit set
        # In that case, try to get the configured limit from container inspect
        if limit <= 0 or limit > 64 * 1024 * 1024 * 1024:  # > 64GB probably host RAM
            try:
                inspect = await loop.run_in_executor(
                    None,
                    lambda: self._docker.containers.get(container_id).attrs,
                )
                host_config = inspect.get("HostConfig", {})
                configured_limit = host_config.get("Memory", 0)
                if configured_limit > 0:
                    limit = configured_limit
            except Exception:
                pass

        if limit <= 0:
            # No memory limit configured; use a sensible default (6GB)
            limit = 6 * 1024 * 1024 * 1024

        # Extract RSS and cache if available
        detailed = mem_stats.get("stats", {})
        rss = detailed.get("rss", detailed.get("active_anon", 0))
        cache = detailed.get("cache", detailed.get("inactive_file", 0))

        fraction = usage / limit if limit > 0 else 0.0

        return MemorySnapshot(
            timestamp=time.time(),
            usage_bytes=usage,
            limit_bytes=limit,
            usage_fraction=fraction,
            rss_bytes=rss,
            cache_bytes=cache,
        )

    def _evaluate_thresholds(
        self, state: ContainerState, snapshot: MemorySnapshot
    ) -> List[ResourceAlert]:
        """Check memory snapshot against thresholds and return any alerts."""
        alerts: List[ResourceAlert] = []
        frac = snapshot.usage_fraction
        trend = state.get_trend()
        now = time.time()

        # Update alert level
        if frac >= MEM_THRESHOLD_RESET:
            state.alert_level = "critical"
        elif frac >= MEM_THRESHOLD_TRIM:
            state.alert_level = "elevated"
        elif frac < MEM_THRESHOLD_WARN:
            state.alert_level = "normal"

        # Emergency (95%+)
        if frac >= MEM_THRESHOLD_EMERGENCY:
            if state.can_send_directive("emergency"):
                alerts.append(ResourceAlert(
                    alert_type="mem_emergency",
                    severity="critical",
                    message=(
                        f"EMERGENCY: Container memory at {frac:.0%} "
                        f"({snapshot.usage_mb:.0f}MB / {snapshot.limit_mb:.0f}MB). "
                        f"OOM kill imminent."
                    ),
                    directive=(
                        "EMERGENCY: Memory critically low. IMMEDIATELY save all findings "
                        "to /pentest/output/ and stop all running processes. "
                        "Do NOT start any new commands."
                    ),
                    container_id=state.container_id,
                    job_id=state.job_id,
                    snapshot=snapshot,
                    trend=trend,
                ))
                state.mark_directive_sent("emergency")

        # Reset threshold (90%)
        elif frac >= MEM_THRESHOLD_RESET:
            if state.can_send_directive("reset"):
                alerts.append(ResourceAlert(
                    alert_type="mem_reset",
                    severity="high",
                    message=(
                        f"Memory at {frac:.0%} ({snapshot.usage_mb:.0f}MB / "
                        f"{snapshot.limit_mb:.0f}MB). Trend: {trend}. "
                        f"Approaching OOM territory."
                    ),
                    directive=(
                        "SAVE_AND_RESET: Memory is dangerously high. "
                        "1) Save all current findings to /pentest/output/ immediately. "
                        "2) Kill any background processes (pkill -f). "
                        "3) Clear /tmp/ files. "
                        "4) Focus remaining iterations on documenting what you found."
                    ),
                    container_id=state.container_id,
                    job_id=state.job_id,
                    snapshot=snapshot,
                    trend=trend,
                ))
                state.mark_directive_sent("reset")

        # Trim threshold (80%)
        elif frac >= MEM_THRESHOLD_TRIM:
            if state.can_send_directive("trim"):
                alerts.append(ResourceAlert(
                    alert_type="mem_trim",
                    severity="medium",
                    message=(
                        f"Memory at {frac:.0%} ({snapshot.usage_mb:.0f}MB / "
                        f"{snapshot.limit_mb:.0f}MB). Trend: {trend}. "
                        f"Triggering context trim."
                    ),
                    directive=(
                        "CONTEXT_TRIM: Memory usage is high. "
                        "Reduce memory footprint: "
                        "1) Stop any unnecessary background scans. "
                        "2) Avoid loading large files into memory. "
                        "3) Use --batch and output-to-file flags for tools. "
                        "4) Clear completed scan results from /tmp/."
                    ),
                    container_id=state.container_id,
                    job_id=state.job_id,
                    snapshot=snapshot,
                    trend=trend,
                ))
                state.mark_directive_sent("trim")

        # Warning threshold (70%) — just log, no directive
        elif frac >= MEM_THRESHOLD_WARN:
            if trend == "rising" and state.can_send_directive("warn"):
                alerts.append(ResourceAlert(
                    alert_type="mem_warn",
                    severity="low",
                    message=(
                        f"Memory at {frac:.0%} ({snapshot.usage_mb:.0f}MB / "
                        f"{snapshot.limit_mb:.0f}MB) and rising. Monitoring closely."
                    ),
                    directive="",  # No directive for warnings, just monitoring
                    container_id=state.container_id,
                    job_id=state.job_id,
                    snapshot=snapshot,
                    trend=trend,
                ))
                state.mark_directive_sent("warn")

        return alerts

    async def _fire_alert(self, alert: ResourceAlert) -> None:
        """Fire an alert through the callback."""
        logger.info(
            "resource_alert",
            alert_type=alert.alert_type,
            severity=alert.severity,
            job_id=alert.job_id,
            container_id=alert.container_id[:12],
            usage_fraction=alert.snapshot.usage_fraction,
            trend=alert.trend,
        )
        if self._on_alert:
            try:
                await self._on_alert(alert.job_id, alert)
            except Exception as e:
                logger.warn("resource_alert_callback_failed",
                            job_id=alert.job_id, error=str(e))

    # -------------------------------------------------------------------
    # Manual trigger (for testing or one-shot checks)
    # -------------------------------------------------------------------

    async def check_now(self, job_id: str) -> Optional[Dict]:
        """Perform an immediate check for a job. Returns stats dict or None."""
        cid = self._job_to_container.get(job_id)
        if not cid:
            return None
        state = self._containers.get(cid)
        if not state:
            return None
        try:
            snapshot = await self._read_container_stats(cid, state)
            if snapshot:
                state.add_snapshot(snapshot)
                alerts = self._evaluate_thresholds(state, snapshot)
                for alert in alerts:
                    await self._fire_alert(alert)
                return snapshot.to_dict()
        except Exception as e:
            logger.warn("resource_check_now_failed", job_id=job_id, error=str(e))
        return None
