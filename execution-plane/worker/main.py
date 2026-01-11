"""
NeuroSploit SaaS v2 - Worker
Executes pentest jobs via Kali containers with Open Interpreter
"""

import os
import asyncio
import json
import structlog
from datetime import datetime
import redis.asyncio as redis
import httpx
import docker

structlog.configure(processors=[
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.JSONRenderer()
])
logger = structlog.get_logger()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8000")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "lm-studio")
WORKER_ID = os.getenv("HOSTNAME", "worker-1")

class Worker:
    def __init__(self):
        self.redis = None
        self.docker_client = docker.from_env()
        self.current_job = None
        
    async def start(self):
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        logger.info("worker_started", worker_id=WORKER_ID, llm_provider=LLM_PROVIDER)
        
        # Subscribe to kill signals
        pubsub = self.redis.pubsub()
        asyncio.create_task(self._listen_control(pubsub))
        
        while True:
            try:
                await self._process_jobs()
            except Exception as e:
                logger.error("worker_error", error=str(e))
            await asyncio.sleep(1)
    
    async def _listen_control(self, pubsub):
        """Listen for kill signals"""
        await pubsub.psubscribe("job:*:control")
        async for message in pubsub.listen():
            if message["type"] == "pmessage":
                job_id = message["channel"].split(":")[1]
                command = message["data"]
                if command == "CANCEL" and self.current_job == job_id:
                    logger.info("job_cancel_received", job_id=job_id)
                    # TODO: Kill container
    
    async def _process_jobs(self):
        # Get job from queue (blocking pop with timeout)
        result = await self.redis.brpop("worker:job_queue", timeout=5)
        
        if result:
            _, job_data = result
            job = json.loads(job_data)
            await self._execute_job(job)
    
    async def _execute_job(self, job: dict):
        job_id = job["job_id"]
        tenant_id = job["tenant_id"]
        self.current_job = job_id
        
        logger.info("job_executing", job_id=job_id, tenant_id=tenant_id)
        
        try:
            # Get job details from control plane
            async with httpx.AsyncClient() as client:
                # In production, this would use proper auth
                resp = await client.get(f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}")
                if resp.status_code != 200:
                    raise Exception(f"Failed to get job details: {resp.status_code}")
                job_details = resp.json()
            
            # Find available Kali container
            container = await self._get_kali_container()
            
            # Execute via Open Interpreter API in container
            result = await self._run_in_container(container, job_details)
            
            # Update job status
            await self._update_job_status(job_id, "completed", result)
            
            logger.info("job_completed", job_id=job_id, findings=len(result.get("findings", [])))
            
        except Exception as e:
            logger.error("job_failed", job_id=job_id, error=str(e))
            await self._update_job_status(job_id, "failed", {"error": str(e)})
        
        finally:
            self.current_job = None
    
    async def _get_kali_container(self):
        """Get an available Kali container from the pool"""
        containers = self.docker_client.containers.list(
            filters={"label": "neurosploit.role=kali-executor", "status": "running"}
        )
        if not containers:
            raise Exception("No Kali containers available")
        return containers[0]
    
    async def _run_in_container(self, container, job_details: dict) -> dict:
        """Execute job in Kali container via Open Interpreter API"""
        
        # Call the agent wrapper API inside the container
        exec_result = container.exec_run(
            cmd=["python", "-c", f"""
import requests
import json

response = requests.post('http://localhost:9000/execute', json={json.dumps({
    "job_id": str(job_details.get("id")),
    "tenant_id": str(job_details.get("tenant_id", "")),
    "scope_id": str(job_details.get("scope_id", "")),
    "target": job_details.get("targets", [""])[0],
    "phase": job_details.get("phase", "RECON"),
    "approved_tools": [],
    "max_intensity": job_details.get("intensity", "medium"),
    "timeout_seconds": job_details.get("timeout_seconds", 3600),
    "auto_run": job_details.get("auto_run", False)
})})

print(response.json())
"""],
            workdir="/pentest"
        )
        
        # Parse result
        try:
            return json.loads(exec_result.output.decode())
        except:
            return {"output": exec_result.output.decode(), "findings": []}
    
    async def _update_job_status(self, job_id: str, status: str, result: dict):
        """Update job status in control plane"""
        try:
            async with httpx.AsyncClient() as client:
                # In production, this would use proper auth
                await client.patch(
                    f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}",
                    json={"status": status, "result": result}
                )
        except Exception as e:
            logger.error("status_update_failed", job_id=job_id, error=str(e))

worker = Worker()

if __name__ == "__main__":
    asyncio.run(worker.start())
