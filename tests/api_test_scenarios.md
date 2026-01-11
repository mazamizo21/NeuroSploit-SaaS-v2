# Phase 1 API Testing Scenarios

## Test Environment Setup

```bash
# Start infrastructure
docker-compose -f docker-compose.infra.yml up -d

# Start control plane
cd control-plane
python -m uvicorn main:app --reload --port 8000

# Start cron worker
cd execution-plane/scheduler
python cron_worker.py
```

## Test 1: MITRE ATT&CK Integration

### 1.1 List All Techniques
```bash
curl http://localhost:8000/api/v1/mitre/techniques?limit=10
```

**Expected:** JSON array of 10 techniques with id, name, description, tactics

### 1.2 Get Specific Technique
```bash
curl http://localhost:8000/api/v1/mitre/techniques/T1046
```

**Expected:** Full details of T1046 (Network Service Discovery)

### 1.3 List All Tactics
```bash
curl http://localhost:8000/api/v1/mitre/tactics
```

**Expected:** 14 tactics (reconnaissance, initial-access, etc.)

### 1.4 Get Tool Techniques
```bash
curl http://localhost:8000/api/v1/mitre/tools/nmap/techniques
```

**Expected:** 4+ techniques associated with nmap

### 1.5 Get Coverage Statistics
```bash
curl http://localhost:8000/api/v1/mitre/coverage
```

**Expected:** 
```json
{
  "total_techniques": 835,
  "total_tactics": 14,
  "total_tools": 91,
  "mapped_tools": 150
}
```

### 1.6 Get AI Context
```bash
curl http://localhost:8000/api/v1/mitre/context?tool_name=nmap
```

**Expected:** Markdown-formatted context for AI with nmap techniques

---

## Test 2: Scheduled Jobs System

### 2.1 Get Common Cron Patterns
```bash
curl http://localhost:8000/api/v1/scheduled-jobs/patterns
```

**Expected:** Dictionary of common patterns (every_15_minutes, hourly, daily_2am, etc.)

### 2.2 Create Scheduled Job
```bash
curl -X POST http://localhost:8000/api/v1/scheduled-jobs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "Daily Security Scan",
    "description": "Automated daily scan at 2 AM",
    "schedule": "0 2 * * *",
    "timezone": "UTC",
    "job_template": {
      "scope_id": "SCOPE_UUID",
      "phase": "VULN_SCAN",
      "targets": ["example.com"],
      "intensity": "medium"
    },
    "is_active": true
  }'
```

**Expected:** Created scheduled job with next_run calculated

### 2.3 List Scheduled Jobs
```bash
curl http://localhost:8000/api/v1/scheduled-jobs \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Array of scheduled jobs for tenant

### 2.4 Get Scheduled Job Details
```bash
curl http://localhost:8000/api/v1/scheduled-jobs/{id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Full details including execution stats

### 2.5 Pause Scheduled Job
```bash
curl -X POST http://localhost:8000/api/v1/scheduled-jobs/{id}/pause \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Job paused, is_paused=true

### 2.6 Resume Scheduled Job
```bash
curl -X POST http://localhost:8000/api/v1/scheduled-jobs/{id}/resume \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Job resumed, next_run recalculated

### 2.7 Update Schedule
```bash
curl -X PUT http://localhost:8000/api/v1/scheduled-jobs/{id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "schedule": "*/30 * * * *",
    "description": "Changed to every 30 minutes"
  }'
```

**Expected:** Schedule updated, next_run recalculated

### 2.8 Delete Scheduled Job
```bash
curl -X DELETE http://localhost:8000/api/v1/scheduled-jobs/{id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** 200 OK, job deleted

---

## Test 3: Team Collaboration

### 3.1 Create Workspace
```bash
curl -X POST http://localhost:8000/api/v1/workspaces \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "Security Team Workspace",
    "description": "Main workspace for security assessments",
    "is_default": true
  }'
```

**Expected:** Workspace created, creator added as admin

### 3.2 List Workspaces
```bash
curl http://localhost:8000/api/v1/workspaces \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Array of workspaces user has access to

### 3.3 Add Member to Workspace
```bash
curl -X POST http://localhost:8000/api/v1/workspaces/{id}/members \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "user_id": "USER_UUID",
    "role": "member",
    "can_create_jobs": true,
    "can_edit_findings": true,
    "can_delete": false
  }'
```

**Expected:** Member added with specified permissions

### 3.4 List Workspace Members
```bash
curl http://localhost:8000/api/v1/workspaces/{id}/members \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Array of members with roles and permissions

### 3.5 Add Comment to Finding
```bash
curl -X POST "http://localhost:8000/api/v1/workspaces/findings/{finding_id}/comments?workspace_id={workspace_id}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "comment": "This is a critical finding that needs immediate attention"
  }'
```

**Expected:** Comment created with user attribution

### 3.6 List Comments on Finding
```bash
curl "http://localhost:8000/api/v1/workspaces/findings/{finding_id}/comments?workspace_id={workspace_id}" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Array of comments with user info

### 3.7 Get Activity Feed
```bash
curl http://localhost:8000/api/v1/workspaces/{id}/activity?limit=50 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Recent activity in workspace (created, commented, etc.)

### 3.8 Remove Member
```bash
curl -X DELETE http://localhost:8000/api/v1/workspaces/{workspace_id}/members/{user_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Member removed (unless last admin)

---

## Test 4: Enhanced Reporting

### 4.1 Calculate Risk Score
```bash
curl http://localhost:8000/api/v1/reports/jobs/{job_id}/risk-score \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:**
```json
{
  "overall_score": 75,
  "attack_surface_score": 60,
  "exploitability_score": 80,
  "impact_score": 85,
  "severity_breakdown": {
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 3,
    "info": 5
  },
  "risk_level": "high",
  "total_findings": 25,
  "recommendations": ["..."],
  "calculated_at": "2026-01-11T19:00:00Z"
}
```

### 4.2 Get Executive Summary
```bash
curl http://localhost:8000/api/v1/reports/jobs/{job_id}/report/executive \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Markdown-formatted executive summary with risk assessment

### 4.3 Get Detailed Report
```bash
curl http://localhost:8000/api/v1/reports/jobs/{job_id}/report/detailed \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Full technical report with all findings

### 4.4 Get HTML Report
```bash
curl http://localhost:8000/api/v1/reports/jobs/{job_id}/report/html \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Styled HTML report (can open in browser)

### 4.5 Get Risk Trends
```bash
curl http://localhost:8000/api/v1/reports/tenants/me/trends?days=30 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:**
```json
{
  "trend": "improving",
  "average_score": 65.5,
  "score_change": -15,
  "data_points": [...]
}
```

### 4.6 Recalculate Risk Score
```bash
curl "http://localhost:8000/api/v1/reports/jobs/{job_id}/risk-score?recalculate=true" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Expected:** Fresh risk score calculation

---

## Test 5: Integration Testing

### 5.1 Complete Workflow Test

1. **Create Workspace**
   ```bash
   POST /api/v1/workspaces
   ```

2. **Add Team Members**
   ```bash
   POST /api/v1/workspaces/{id}/members
   ```

3. **Create Scheduled Job**
   ```bash
   POST /api/v1/scheduled-jobs
   ```

4. **Wait for Job Execution** (or trigger manually)
   - CronWorker creates Job from template
   - Job executes with MITRE-aware AI
   - Findings tagged with MITRE techniques

5. **Calculate Risk Score**
   ```bash
   GET /api/v1/reports/jobs/{job_id}/risk-score
   ```

6. **Add Comments to Findings**
   ```bash
   POST /api/v1/workspaces/findings/{id}/comments
   ```

7. **Generate Reports**
   ```bash
   GET /api/v1/reports/jobs/{job_id}/report/executive
   GET /api/v1/reports/jobs/{job_id}/report/html
   ```

8. **Check Activity Feed**
   ```bash
   GET /api/v1/workspaces/{id}/activity
   ```

9. **View Trends**
   ```bash
   GET /api/v1/reports/tenants/me/trends
   ```

**Expected:** All features work together seamlessly

---

## Test Results Template

| Test | Status | Notes |
|------|--------|-------|
| MITRE - List Techniques | ⏳ | |
| MITRE - Get Technique | ⏳ | |
| MITRE - Tool Mapping | ⏳ | |
| MITRE - Coverage Stats | ⏳ | |
| Scheduled - Create Job | ⏳ | |
| Scheduled - List Jobs | ⏳ | |
| Scheduled - Pause/Resume | ⏳ | |
| Workspace - Create | ⏳ | |
| Workspace - Add Member | ⏳ | |
| Workspace - Comments | ⏳ | |
| Workspace - Activity Feed | ⏳ | |
| Reports - Risk Score | ⏳ | |
| Reports - Executive Summary | ⏳ | |
| Reports - HTML Report | ⏳ | |
| Reports - Trends | ⏳ | |
| Integration - Full Workflow | ⏳ | |

---

## Performance Benchmarks

| Metric | Target | Actual |
|--------|--------|--------|
| MITRE Technique Lookup | <50ms | |
| Risk Score Calculation | <500ms | |
| Report Generation | <2s | |
| Scheduled Job Check | <100ms | |
| Activity Feed Load | <200ms | |

---

## Known Issues

1. **Dependencies:** croniter, sqlalchemy need to be installed in test environment
2. **Authentication:** Tests require valid JWT tokens
3. **Database:** PostgreSQL must be running
4. **Redis:** Redis must be running for session management

---

## Next Steps

1. ✅ Unit tests for core services (PASSED)
2. ⏳ API endpoint tests (requires running servers)
3. ⏳ Integration workflow test
4. ⏳ Performance benchmarks
5. ⏳ Load testing
6. ⏳ Security testing
