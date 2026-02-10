# Spec 001: Job Lifecycle Resilience (Container Restart Orphan Fix)

## Problem Statement

When a Kali executor container restarts (OOM kill, Docker daemon restart, resource limits), in-flight jobs lose their container mapping. The worker that launched the job may not detect the container death, leaving the job stuck in `running` status forever. The scheduler thinks the slot is occupied, reducing effective concurrency.

### Current Behavior
1. Worker execs Dynamic Agent into a Kali container
2. Kali container restarts (OOM, crash, docker restart)
3. Worker's subprocess hangs or returns error, but job status stays `running`
4. Redis still has `job:<id>:kali_container` pointing to dead container
5. Scheduler never reclaims the slot (until the 1hr ACTIVE_WINDOW_SECONDS expires in supervisor)

### Root Cause
- Worker `_run_in_container()` catches the Docker exec error but the `finally` block only clears `self.current_job`
- No heartbeat between worker and kali container to detect death
- No periodic job health check in scheduler

## Proposed Solution

### 1. Container Health Watchdog (Worker-side)
Add a background task in the worker that periodically checks if the Kali container for the current job is still running:

```python
async def _watch_container_health(self, container_id: str, job_id: str):
    while self.current_job == job_id:
        try:
            container = self.docker_client.containers.get(container_id)
            if container.status != "running":
                logger.warn("kali_container_died", job_id=job_id, status=container.status)
                self._cancel_event.set()
                break
        except docker.errors.NotFound:
            logger.warn("kali_container_gone", job_id=job_id)
            self._cancel_event.set()
            break
        await asyncio.sleep(10)
```

### 2. Scheduler Stale Job Reaper
Add a periodic sweep in the scheduler that checks for jobs stuck in `running` beyond their timeout:

```python
async def _reap_stale_jobs(self):
    """Every 60s, check for jobs stuck in running beyond their timeout."""
    while True:
        for job_id, meta in list(self.running_jobs.items()):
            elapsed = (datetime.utcnow() - meta["started"]).total_seconds()
            if elapsed > meta.get("timeout", 3600) + 300:  # 5min grace
                # Publish timeout
                await self.redis.publish(f"job:{job_id}:status", 
                    json.dumps({"status": "timeout", "reason": "stale_reaper"}))
                del self.running_jobs[job_id]
        await asyncio.sleep(60)
```

### 3. Job Resume on Container Recovery
Leverage the existing `kali-output` volume persistence:
- When a Kali container comes back, the `/pentest/output/<job_id>` directory still exists
- Add a `resume` flag in Redis: `job:<id>:resume = true`
- Worker checks for resume flag before starting a new agent session
- Dynamic Agent loads previous `vuln_tracker.json`, `mitre_coverage.json`, and conversation state

### 4. Redis Expiry on Container Mappings
Set TTL on `job:<id>:kali_container` keys equal to job timeout + buffer. This ensures stale mappings auto-expire.

## Acceptance Criteria
- [ ] Worker detects Kali container death within 15 seconds
- [ ] Job transitions to `failed` (with `container_died` reason) or is re-queued for resume
- [ ] Scheduler reclaims concurrency slot immediately on container death
- [ ] Resumed jobs continue from last checkpoint, not from scratch
- [ ] No orphan `running` jobs after 2x timeout period

## Files to Modify
- `execution-plane/worker/main.py` — Add container watchdog
- `execution-plane/scheduler/main.py` — Add stale job reaper
- `kali-executor/open-interpreter/dynamic_agent.py` — Add checkpoint/resume logic
- `docker-compose.yml` — Ensure volume mounts support resume

## Risk Assessment
- **Low**: Container health polling is cheap (10s interval)
- **Medium**: Resume logic needs careful state reconstruction to avoid duplicate findings
- **Low**: Redis key TTL is safe and doesn't affect running jobs
