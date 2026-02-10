"""
TazoSploit SaaS v2 - Job Scheduler
Distributes jobs from Control Plane to Workers
"""

import os
import asyncio
import json
import structlog
from datetime import datetime
import redis.asyncio as redis
from fastapi import FastAPI
import httpx

structlog.configure(processors=[
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.JSONRenderer()
])
logger = structlog.get_logger()

app = FastAPI(title="TazoSploit Scheduler")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://api:8000")
MAX_CONCURRENT = int(os.getenv("MAX_CONCURRENT_JOBS", "10"))

class JobScheduler:
    def __init__(self):
        self.redis = None
        self.running_jobs = {}
        self._status_task = None
        
    async def start(self):
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        logger.info("scheduler_started", max_concurrent=MAX_CONCURRENT)

        # Listen for job status updates so we can free slots when jobs complete
        self._status_task = asyncio.create_task(self._listen_status_updates())
        
        while True:
            try:
                await self._process_queues()
            except Exception as e:
                logger.error("scheduler_error", error=str(e))
            await asyncio.sleep(1)

    async def _listen_status_updates(self):
        """Listen for job:*:status messages and release completed jobs.
        
        Wraps in try/except with exponential backoff to survive Redis disconnects (N5).
        """
        backoff = 1
        max_backoff = 60
        while True:
            try:
                if not self.redis:
                    self.redis = redis.from_url(REDIS_URL, decode_responses=True)
                pubsub = self.redis.pubsub()
                await pubsub.psubscribe("job:*:status")
                backoff = 1  # reset on successful connection
                async for message in pubsub.listen():
                    if message.get("type") != "pmessage":
                        continue
                    channel = message.get("channel", "")
                    data = message.get("data")
                    # Channel format: job:<id>:status
                    try:
                        parts = str(channel).split(":")
                        job_id = parts[1] if len(parts) > 1 else None
                        payload = json.loads(data) if isinstance(data, str) else data
                        status = (payload or {}).get("status")
                        if job_id and status in {"completed", "failed", "cancelled", "timeout"}:
                            if job_id in self.running_jobs:
                                del self.running_jobs[job_id]
                                logger.info("job_slot_released", job_id=job_id, status=status)
                            # N2: On cancel/terminal, mark job as terminal in Redis to prevent re-dispatch
                            if status == "cancelled":
                                await self.redis.set(f"job:{job_id}:terminal", "cancelled", ex=86400)
                                # Remove from worker queue to prevent re-dispatch
                                await self.redis.lrem("worker:job_queue", 0, json.dumps({"job_id": job_id}))
                                # Also remove by scanning (job_data may differ in other fields)
                                try:
                                    queue_items = await self.redis.lrange("worker:job_queue", 0, -1)
                                    for item in queue_items:
                                        try:
                                            parsed = json.loads(item)
                                            if parsed.get("job_id") == job_id:
                                                await self.redis.lrem("worker:job_queue", 0, item)
                                        except Exception:
                                            continue
                                except Exception:
                                    pass
                                logger.info("cancelled_job_cleaned", job_id=job_id)
                    except Exception:
                        continue
            except Exception as e:
                logger.error("status_listener_error", error=str(e), backoff=backoff)
                try:
                    await pubsub.close()
                except Exception:
                    pass
                self.redis = None
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)
    
    async def _process_queues(self):
        # Get all tenant queues
        keys = await self.redis.keys("tenant:*:job_queue")
        
        for key in keys:
            if len(self.running_jobs) >= MAX_CONCURRENT:
                break
                
            job_id = await self.redis.rpop(key)
            if job_id:
                tenant_id = key.split(":")[1]
                await self._dispatch_job(tenant_id, job_id)
    
    async def _dispatch_job(self, tenant_id: str, job_id: str):
        # N2: Check if job is already in a terminal state (cancelled/completed) before dispatching
        terminal = await self.redis.get(f"job:{job_id}:terminal")
        if terminal:
            logger.info("job_dispatch_skipped_terminal", job_id=job_id, terminal_status=terminal)
            return

        logger.info("job_dispatching", job_id=job_id, tenant_id=tenant_id)
        
        # Publish to worker queue
        await self.redis.lpush("worker:job_queue", json.dumps({
            "job_id": job_id,
            "tenant_id": tenant_id,
            "dispatched_at": datetime.utcnow().isoformat()
        }))
        
        self.running_jobs[job_id] = {"tenant_id": tenant_id, "started": datetime.utcnow()}

scheduler = JobScheduler()

@app.on_event("startup")
async def startup():
    # N7: Filter /health from uvicorn access logs at startup (covers both __main__ and uvicorn CLI)
    import logging
    class _HealthFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return "GET /health" not in record.getMessage()
    logging.getLogger("uvicorn.access").addFilter(_HealthFilter())
    asyncio.create_task(scheduler.start())

@app.get("/health")
async def health():
    return {"status": "healthy", "running_jobs": len(scheduler.running_jobs)}

if __name__ == "__main__":
    import uvicorn
    import logging

    # N7: Filter /health from access logs to reduce noise (99% of log lines)
    class HealthCheckFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            message = record.getMessage()
            if "GET /health" in message:
                return False
            return True

    logging.getLogger("uvicorn.access").addFilter(HealthCheckFilter())

    uvicorn.run(app, host="0.0.0.0", port=9001)
