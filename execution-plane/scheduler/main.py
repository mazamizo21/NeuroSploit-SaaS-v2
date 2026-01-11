"""
NeuroSploit SaaS v2 - Job Scheduler
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

app = FastAPI(title="NeuroSploit Scheduler")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8000")
MAX_CONCURRENT = int(os.getenv("MAX_CONCURRENT_JOBS", "10"))

class JobScheduler:
    def __init__(self):
        self.redis = None
        self.running_jobs = {}
        
    async def start(self):
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        logger.info("scheduler_started", max_concurrent=MAX_CONCURRENT)
        
        while True:
            try:
                await self._process_queues()
            except Exception as e:
                logger.error("scheduler_error", error=str(e))
            await asyncio.sleep(1)
    
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
    asyncio.create_task(scheduler.start())

@app.get("/health")
async def health():
    return {"status": "healthy", "running_jobs": len(scheduler.running_jobs)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9001)
