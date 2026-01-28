#!/usr/bin/env python3
"""
TazoSploit SaaS v2 - Cron Worker
Background worker that monitors scheduled jobs and triggers execution
"""

import os
import sys
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../control-plane'))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, and_

from api.models import ScheduledJob, Job, JobStatus
from services.scheduler_service import SchedulerService

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CronWorker:
    """Background worker for scheduled job execution"""
    
    def __init__(self, check_interval: int = 60):
        """
        Initialize cron worker
        
        Args:
            check_interval: Seconds between checks (default: 60)
        """
        self.check_interval = check_interval
        self.running = False
        
        # Database setup
        database_url = os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://tazosploit:tazosploit@localhost:5432/tazosploit"
        )
        self.engine = create_async_engine(database_url, echo=False)
        self.async_session = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
    
    async def start(self):
        """Start the worker"""
        self.running = True
        logger.info("Cron worker started", extra={"check_interval": self.check_interval})
        
        while self.running:
            try:
                await self._check_and_execute()
                await asyncio.sleep(self.check_interval)
            except KeyboardInterrupt:
                logger.info("Received shutdown signal")
                self.running = False
            except Exception as e:
                logger.error(f"Error in worker loop: {e}", exc_info=True)
                await asyncio.sleep(self.check_interval)
    
    async def _check_and_execute(self):
        """Check for due scheduled jobs and execute them"""
        async with self.async_session() as session:
            # Find scheduled jobs that are due
            now = datetime.utcnow()
            
            query = select(ScheduledJob).where(
                and_(
                    ScheduledJob.is_active == True,
                    ScheduledJob.is_paused == False,
                    ScheduledJob.next_run <= now
                )
            )
            
            result = await session.execute(query)
            due_jobs = result.scalars().all()
            
            if due_jobs:
                logger.info(f"Found {len(due_jobs)} scheduled jobs due for execution")
            
            for scheduled_job in due_jobs:
                try:
                    await self._execute_scheduled_job(session, scheduled_job)
                except Exception as e:
                    logger.error(
                        f"Failed to execute scheduled job {scheduled_job.id}: {e}",
                        exc_info=True
                    )
    
    async def _execute_scheduled_job(self, session: AsyncSession, scheduled_job: ScheduledJob):
        """Execute a scheduled job"""
        logger.info(
            f"Executing scheduled job: {scheduled_job.name}",
            extra={
                "scheduled_job_id": str(scheduled_job.id),
                "tenant_id": str(scheduled_job.tenant_id)
            }
        )
        
        try:
            # Create job from template
            job_template = scheduled_job.job_template
            
            job = Job(
                tenant_id=scheduled_job.tenant_id,
                created_by=scheduled_job.created_by,
                name=f"{scheduled_job.name} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
                description=f"Scheduled execution of: {scheduled_job.name}",
                scope_id=job_template.get("scope_id"),
                phase=job_template.get("phase", "RECON"),
                targets=job_template.get("targets", []),
                intensity=job_template.get("intensity", "medium"),
                timeout_seconds=job_template.get("timeout_seconds", 3600),
                auto_run=True,
                status=JobStatus.PENDING
            )
            
            session.add(job)
            
            # Update scheduled job stats
            scheduled_job.last_run = datetime.utcnow()
            scheduled_job.total_runs += 1
            
            # Calculate next run
            scheduled_job.next_run = SchedulerService.calculate_next_run(
                scheduled_job.schedule,
                base_time=datetime.utcnow(),
                timezone=scheduled_job.timezone
            )
            
            await session.commit()
            
            logger.info(
                f"Created job {job.id} from scheduled job {scheduled_job.id}",
                extra={
                    "job_id": str(job.id),
                    "next_run": scheduled_job.next_run.isoformat()
                }
            )
            
            # TODO: Trigger job execution via execution plane
            # For now, the job is created and will be picked up by workers
            
        except Exception as e:
            scheduled_job.failed_runs += 1
            await session.commit()
            raise
    
    async def stop(self):
        """Stop the worker"""
        self.running = False
        await self.engine.dispose()
        logger.info("Cron worker stopped")

async def main():
    """Main entry point"""
    check_interval = int(os.getenv("CRON_CHECK_INTERVAL", "60"))
    
    worker = CronWorker(check_interval=check_interval)
    
    try:
        await worker.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await worker.stop()

if __name__ == "__main__":
    asyncio.run(main())
