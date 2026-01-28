"""
TazoSploit Cron Scheduler
Professional pentest task scheduling with APScheduler backend
"""

import os
import json
import uuid
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path
from dataclasses import asdict

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR, EVENT_JOB_MISSED

from .job_types import Job, JobType, JobStatus, JobPriority, BaseJobConfig, ScanJob, ReconJob
from .job_parser import JobParser


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CronScheduler:
    """
    Professional pentest task scheduler using APScheduler
    
    Features:
        - Natural language time parsing
        - Job persistence (JSON)
        - Job lifecycle management
        - One-time and recurring jobs
        - Priority-based execution
        - Error handling and retries
        - Job history tracking
    """
    
    def __init__(self, jobs_dir: str = "memory/jobs"):
        """
        Initialize the scheduler
        
        Args:
            jobs_dir: Directory for job persistence (default: memory/jobs)
        """
        self.jobs_dir = Path(jobs_dir)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        
        self.jobs_file = self.jobs_dir / "jobs.json"
        self.history_file = self.jobs_dir / "history.json"
        
        # In-memory job storage
        self.jobs: Dict[str, Job] = {}
        self.job_history: List[Dict[str, Any]] = []
        
        # Job parser for natural language
        self.parser = JobParser()
        
        # Configure APScheduler
        jobstores = {
            'default': MemoryJobStore()
        }
        executors = {
            'default': AsyncIOExecutor()
        }
        job_defaults = {
            'coalesce': True,
            'max_instances': 3,
            'misfire_grace_time': 300  # 5 minutes
        }
        
        self.scheduler = AsyncIOScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone='UTC'
        )
        
        # Track job execution
        self.scheduler.add_listener(
            self._job_executed_listener,
            EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED
        )
        
        # Load persisted jobs
        self._load_jobs()
        self._load_history()
    
    def start(self):
        """Start the scheduler"""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Scheduler started")
    
    def shutdown(self, wait: bool = True):
        """Shutdown the scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=wait)
            logger.info("Scheduler shutdown")
    
    def schedule(
        self,
        description: str,
        natural_time: str,
        job_config: BaseJobConfig,
        job_id: Optional[str] = None,
        callback: Optional[Callable] = None
    ) -> Job:
        """
        Schedule a job with natural language time
        
        Args:
            description: Human-readable description (e.g., "scan target.com")
            natural_time: Natural language time (e.g., "in 2 hours", "daily at 3am")
            job_config: Job configuration object
            job_id: Optional custom job ID
            callback: Optional callback function to execute
        
        Returns:
            Scheduled Job object
        """
        # Parse natural language time
        try:
            scheduled_time, cron_expr = self.parser.parse_schedule(natural_time)
        except ValueError as e:
            logger.error(f"Failed to parse schedule: {e}")
            raise
        
        # Generate job ID
        job_id = job_id or str(uuid.uuid4())
        
        # Create job
        job = Job(
            id=job_id,
            config=job_config,
            status=JobStatus.SCHEDULED,
            scheduled_at=scheduled_time
        )
        job.config.name = description
        
        # Store job
        self.jobs[job_id] = job
        
        # Schedule with APScheduler
        if cron_expr:
            # Recurring job
            trigger = CronTrigger.from_crontab(cron_expr)
            logger.info(f"Scheduling recurring job '{description}' with cron: {cron_expr}")
        else:
            # One-time job
            trigger = DateTrigger(run_date=scheduled_time)
            logger.info(f"Scheduling one-time job '{description}' at {scheduled_time}")
        
        # Add job to scheduler
        self.scheduler.add_job(
            func=callback or self._execute_job,
            trigger=trigger,
            id=job_id,
            args=[job_id],
            kwargs={'callback': callback},
            name=description,
            replace_existing=True
        )
        
        # Persist jobs
        self._save_jobs()
        
        return job
    
    def schedule_simple(
        self,
        description: str,
        natural_time: str,
        job_type: JobType = JobType.SCAN,
        **kwargs
    ) -> Job:
        """
        Schedule a job with simple parameters
        
        Args:
            description: Human-readable description
            natural_time: Natural language time
            job_type: Type of job to create
            **kwargs: Additional parameters for job config
        
        Returns:
            Scheduled Job object
        """
        # Extract parameters from description
        params = self.parser.extract_job_params(description)
        params.update(kwargs)
        
        # Create appropriate job config
        job_configs = {
            JobType.SCAN: ScanJob,
            JobType.RECON: ReconJob,
        }
        
        job_config_class = job_configs.get(job_type, ScanJob)
        job_config = job_config_class(
            name=description,
            description=description,
            **params
        )
        
        return self.schedule(description, natural_time, job_config)
    
    def _execute_job(self, job_id: str, callback: Optional[Callable] = None):
        """
        Execute a job (internal method called by APScheduler)
        
        Args:
            job_id: Job identifier
            callback: Optional callback function
        """
        job = self.jobs.get(job_id)
        if not job:
            logger.error(f"Job not found: {job_id}")
            return
        
        # Update job status
        job.status = JobStatus.RUNNING
        job.started_at = datetime.utcnow()
        job.add_log("Job execution started")
        self._save_jobs()
        
        try:
            # Execute callback if provided
            if callback:
                result = callback(job)
                job.result = result if isinstance(result, dict) else {'output': result}
            else:
                # Default execution (placeholder)
                job.add_log(f"Executing {job.config.job_type.value} job")
                job.result = self._default_job_execution(job)
            
            # Update job status to completed
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            job.add_log("Job completed successfully")
            
            # Add to history
            self._add_to_history(job)
            
        except Exception as e:
            # Handle failure
            job.status = JobStatus.FAILED
            job.completed_at = datetime.utcnow()
            job.error_message = str(e)
            job.add_log(f"Job failed: {str(e)}")
            
            # Retry if configured
            if job.config.retry_on_failure and job.retry_count < job.config.max_retries:
                job.retry_count += 1
                job.status = JobStatus.PENDING
                job.add_log(f"Retrying job (attempt {job.retry_count}/{job.config.max_retries})")
                
                # Reschedule after delay
                retry_delay = timedelta(minutes=5 * job.retry_count)
                new_scheduled_time = datetime.utcnow() + retry_delay
                job.scheduled_at = new_scheduled_time
                
                # Update scheduler trigger
                self.scheduler.reschedule_job(
                    job_id,
                    trigger=DateTrigger(run_date=new_scheduled_time)
                )
            else:
                # Max retries exceeded
                self._add_to_history(job)
        
        finally:
            self._save_jobs()
    
    def _default_job_execution(self, job: Job) -> Dict[str, Any]:
        """
        Default job execution logic (placeholder)
        
        In a real implementation, this would:
        - Spawn sub-agents for execution
        - Run pentest tools
        - Collect results
        
        Args:
            job: Job to execute
        
        Returns:
            Execution results
        """
        logger.info(f"Executing job: {job.config.name}")
        job.add_log(f"Job type: {job.config.job_type.value}")
        
        # Placeholder execution
        return {
            'job_id': job.id,
            'job_type': job.config.job_type.value,
            'status': 'completed',
            'message': 'Job executed successfully (placeholder)',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _job_executed_listener(self, event):
        """APScheduler event listener for job execution"""
        job_id = event.job_id
        
        if event.exception:
            logger.error(f"Job {job_id} failed: {event.exception}")
        elif event.code == EVENT_JOB_MISSED:
            logger.warning(f"Job {job_id} missed scheduled run")
        else:
            logger.info(f"Job {job_id} executed successfully")
    
    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a scheduled job
        
        Args:
            job_id: Job identifier
        
        Returns:
            True if cancelled, False if not found
        """
        try:
            self.scheduler.remove_job(job_id)
            
            if job_id in self.jobs:
                self.jobs[job_id].status = JobStatus.CANCELLED
                self.jobs[job_id].completed_at = datetime.utcnow()
                self.jobs[job_id].add_log("Job cancelled")
                self._save_jobs()
                self._add_to_history(self.jobs[job_id])
            
            logger.info(f"Job cancelled: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to cancel job {job_id}: {e}")
            return False
    
    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        return self.jobs.get(job_id)
    
    def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        job_type: Optional[JobType] = None
    ) -> List[Job]:
        """
        List jobs with optional filters
        
        Args:
            status: Filter by status
            job_type: Filter by job type
        
        Returns:
            List of matching jobs
        """
        jobs = list(self.jobs.values())
        
        if status:
            jobs = [j for j in jobs if j.status == status]
        
        if job_type:
            jobs = [j for j in jobs if j.config.job_type == job_type]
        
        return jobs
    
    def get_job_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get job history"""
        return self.job_history[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics"""
        jobs = list(self.jobs.values())
        
        status_counts = {}
        for status in JobStatus:
            status_counts[status.value] = sum(1 for j in jobs if j.status == status)
        
        type_counts = {}
        for job_type in JobType:
            type_counts[job_type.value] = sum(1 for j in jobs if j.config.job_type == job_type)
        
        return {
            'total_jobs': len(jobs),
            'jobs_by_status': status_counts,
            'jobs_by_type': type_counts,
            'running_jobs': status_counts.get('running', 0),
            'scheduled_jobs': status_counts.get('scheduled', 0),
            'scheduler_running': self.scheduler.running,
            'next_fire_time': self.scheduler.get_next_fire_time()
        }
    
    def _add_to_history(self, job: Job):
        """Add job to history"""
        history_entry = job.to_dict()
        self.job_history.append(history_entry)
        
        # Keep history size manageable
        if len(self.job_history) > 1000:
            self.job_history = self.job_history[-1000:]
        
        self._save_history()
    
    def _save_jobs(self):
        """Save jobs to JSON file"""
        try:
            jobs_data = {job_id: job.to_dict() for job_id, job in self.jobs.items()}
            
            with open(self.jobs_file, 'w') as f:
                json.dump(jobs_data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save jobs: {e}")
    
    def _load_jobs(self):
        """Load jobs from JSON file"""
        try:
            if self.jobs_file.exists():
                with open(self.jobs_file, 'r') as f:
                    jobs_data = json.load(f)
                
                for job_id, job_data in jobs_data.items():
                    try:
                        self.jobs[job_id] = Job.from_dict(job_data)
                    except Exception as e:
                        logger.error(f"Failed to load job {job_id}: {e}")
                
                logger.info(f"Loaded {len(self.jobs)} jobs from storage")
        except Exception as e:
            logger.error(f"Failed to load jobs: {e}")
    
    def _save_history(self):
        """Save job history to JSON file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.job_history, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save history: {e}")
    
    def _load_history(self):
        """Load job history from JSON file"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    self.job_history = json.load(f)
                
                logger.info(f"Loaded {len(self.job_history)} history entries")
        except Exception as e:
            logger.error(f"Failed to load history: {e}")


# Singleton instance
_scheduler_instance: Optional[CronScheduler] = None


def get_scheduler(jobs_dir: str = "memory/jobs") -> CronScheduler:
    """Get or create scheduler singleton"""
    global _scheduler_instance
    
    if _scheduler_instance is None:
        _scheduler_instance = CronScheduler(jobs_dir=jobs_dir)
        _scheduler_instance.start()
    
    return _scheduler_instance
