# Scheduler System

**Last Updated:** 2026-02-05

This document covers the two scheduling layers in TazoSploit:

1. **Local/CLI scheduler** (APScheduler-based) for standalone runs.
2. **SaaS scheduler** (database-backed) for tenant scheduled jobs in the control/execution planes.

---

## 1) Local/CLI Scheduler (APScheduler)

**Location:** `schedulers/`

Key files:
- `schedulers/cron_scheduler.py` — core APScheduler wrapper
- `schedulers/job_types.py` — job configuration models
- `schedulers/job_parser.py` — natural language time parsing

**Purpose:** schedule local tasks like recon scans, recurring checks, and report generation.

**Usage Example:**

```python
from schedulers import CronScheduler, ScanJob

scheduler = CronScheduler()
job = scheduler.schedule(
    description="Scan target.com",
    natural_time="daily at 3am",
    job_config=ScanJob(target="target.com", scan_type="full")
)
```

**Persistence:**
- Active jobs: `memory/jobs/jobs.json`
- History: `memory/jobs/history.json`

---

## 2) SaaS Scheduler (DB + Execution Plane)

This supports multi-tenant scheduled jobs created via API and executed by the execution plane.

**Control Plane:**
- Schedules are stored in Postgres (`ScheduledJob` table).
- API endpoints manage schedules (`/api/v1/scheduled-jobs`).

**Execution Plane:**
- `execution-plane/scheduler/cron_worker.py`
  - polls for due scheduled jobs
  - creates a `Job` record from the template
  - dispatches the job to Redis queue `tenant:{tenant_id}:job_queue`

**Worker Pipeline:**
- `execution-plane/scheduler/main.py` moves tenant queues into `worker:job_queue`
- `execution-plane/main.py` pulls from `worker:job_queue` and executes in Kali

---

## Configuration

Environment variables:
- `CRON_CHECK_INTERVAL` — polling interval for scheduled jobs (seconds)
- `MAX_CONCURRENT_JOBS` — scheduler concurrency cap
- `REDIS_URL` — Redis connection for job queue
- `DATABASE_URL` — Postgres connection for scheduled job data

---

## Operational Notes

- Scheduled jobs are created with `auto_run=True` and dispatched immediately.
- The scheduler listens to Redis `job:*:status` to free concurrency slots.
- For SaaS schedules, ensure Redis + API are reachable by the scheduler container.

---

## Troubleshooting

- **Jobs created but not running:** check Redis connectivity and `tenant:{id}:job_queue` entries.
- **Concurrency stuck:** verify scheduler is receiving `job:*:status` pubsub messages.
- **No schedules firing:** verify `CRON_CHECK_INTERVAL` and DB time synchronization.
