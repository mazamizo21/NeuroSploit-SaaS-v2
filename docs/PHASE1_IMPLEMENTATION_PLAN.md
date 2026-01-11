# Phase 1 Implementation Plan

## Overview
Implement foundational enterprise features to compete with commercial pentesting platforms.

## Timeline: 1-2 months

## Features to Implement

### 1. Continuous Scanning Engine
**Goal:** 24/7 automated testing, not just on-demand

**Components:**
- Scheduled job system with cron-like scheduling
- Background worker for recurring scans
- Real-time status monitoring
- Alert system for critical findings

### 2. MITRE ATT&CK Integration
**Goal:** Deep framework integration with local database

**Components:**
- Download and store MITRE ATT&CK STIX 2.1 data locally
- Map tools to techniques (T1234)
- Tag findings with MITRE techniques
- Coverage visualization
- Make AI aware of MITRE context

### 3. Team Collaboration
**Goal:** Multi-user workspaces with shared findings

**Components:**
- Workspace model (shared context)
- User roles (admin, operator, viewer, auditor)
- Comments/annotations on findings
- Activity feed
- Notifications

### 4. Enhanced Reporting
**Goal:** Executive-friendly reports with risk scoring

**Components:**
- Executive summary generation
- Risk scoring algorithm
- Trend analysis over time
- PDF/HTML export
- Compliance mapping (basic)

## Technical Architecture

### Database Schema Additions

```sql
-- Scheduled Jobs
CREATE TABLE scheduled_jobs (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    name VARCHAR(255),
    schedule VARCHAR(100),  -- cron expression
    job_template JSONB,     -- Job configuration
    is_active BOOLEAN,
    last_run TIMESTAMP,
    next_run TIMESTAMP,
    created_at TIMESTAMP
);

-- MITRE ATT&CK Database
CREATE TABLE mitre_techniques (
    id VARCHAR(20) PRIMARY KEY,  -- T1234
    name VARCHAR(500),
    description TEXT,
    tactic VARCHAR(100),
    platform JSONB,
    data_sources JSONB,
    detection TEXT,
    mitigation TEXT,
    version VARCHAR(20)
);

CREATE TABLE mitre_tool_mapping (
    tool_name VARCHAR(100),
    technique_id VARCHAR(20) REFERENCES mitre_techniques(id),
    confidence VARCHAR(20),  -- high, medium, low
    PRIMARY KEY (tool_name, technique_id)
);

-- Workspaces (Team Collaboration)
CREATE TABLE workspaces (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    name VARCHAR(255),
    description TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP
);

CREATE TABLE workspace_members (
    workspace_id UUID REFERENCES workspaces(id),
    user_id UUID REFERENCES users(id),
    role VARCHAR(50),  -- admin, member, viewer
    joined_at TIMESTAMP,
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE finding_comments (
    id UUID PRIMARY KEY,
    finding_id UUID REFERENCES findings(id),
    user_id UUID REFERENCES users(id),
    comment TEXT,
    created_at TIMESTAMP
);

-- Risk Scoring
CREATE TABLE risk_scores (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    job_id UUID REFERENCES jobs(id),
    overall_score INTEGER,  -- 0-100
    attack_surface_score INTEGER,
    exploitability_score INTEGER,
    impact_score INTEGER,
    calculated_at TIMESTAMP
);
```

## Implementation Steps

### Step 1: MITRE ATT&CK Integration (Week 1)

1. **Download MITRE ATT&CK Data**
   - Clone: https://github.com/mitre-attack/attack-stix-data
   - Use enterprise-attack.json (latest)
   - Parse STIX 2.1 JSON format

2. **Create MITRE Database Service**
   - `control-plane/services/mitre_service.py`
   - Load STIX data into PostgreSQL
   - Create tool-to-technique mapping
   - Provide query API

3. **Update Dynamic Agent**
   - Add MITRE context to system prompt
   - Include technique descriptions
   - Tag commands with techniques
   - Store technique IDs in findings

4. **Create MITRE API Endpoints**
   - GET /api/v1/mitre/techniques
   - GET /api/v1/mitre/techniques/{id}
   - GET /api/v1/mitre/coverage (show what we can test)
   - GET /api/v1/mitre/gaps (show what we can't test)

### Step 2: Scheduled Jobs System (Week 2)

1. **Create Scheduler Service**
   - `execution-plane/scheduler/cron_scheduler.py`
   - Parse cron expressions
   - Calculate next run times
   - Trigger job creation

2. **Add Scheduled Job Model**
   - Database migration
   - API endpoints for CRUD
   - Validation logic

3. **Background Worker**
   - Monitor scheduled_jobs table
   - Create jobs when due
   - Update last_run/next_run
   - Handle failures/retries

4. **API Endpoints**
   - POST /api/v1/scheduled-jobs
   - GET /api/v1/scheduled-jobs
   - PUT /api/v1/scheduled-jobs/{id}
   - DELETE /api/v1/scheduled-jobs/{id}
   - POST /api/v1/scheduled-jobs/{id}/pause
   - POST /api/v1/scheduled-jobs/{id}/resume

### Step 3: Team Collaboration (Week 3)

1. **Workspace Model**
   - Database migration
   - Workspace CRUD API
   - Member management

2. **Comments System**
   - Add comments to findings
   - Real-time updates (WebSocket)
   - Notifications

3. **Activity Feed**
   - Track all workspace actions
   - Filter by user/resource
   - Export audit trail

4. **API Endpoints**
   - POST /api/v1/workspaces
   - GET /api/v1/workspaces
   - POST /api/v1/workspaces/{id}/members
   - POST /api/v1/findings/{id}/comments
   - GET /api/v1/workspaces/{id}/activity

### Step 4: Enhanced Reporting (Week 4)

1. **Risk Scoring Algorithm**
   - Calculate attack surface score
   - Calculate exploitability score
   - Calculate impact score
   - Overall risk score (0-100)

2. **Executive Summary Generator**
   - AI-powered summary
   - Key findings highlight
   - Risk trend analysis
   - Recommendations

3. **Report Templates**
   - HTML template with charts
   - PDF generation (WeasyPrint)
   - Executive vs Technical views
   - Compliance mapping

4. **API Endpoints**
   - GET /api/v1/jobs/{id}/report (HTML)
   - GET /api/v1/jobs/{id}/report/pdf
   - GET /api/v1/jobs/{id}/risk-score
   - GET /api/v1/tenants/me/trends

## Testing Strategy

### Unit Tests
- MITRE data parser
- Cron expression parser
- Risk scoring algorithm
- Report generator

### Integration Tests
- Scheduled job execution
- MITRE technique tagging
- Workspace permissions
- Report generation

### End-to-End Tests
1. Create scheduled job
2. Wait for execution
3. Verify MITRE tagging
4. Add comments to findings
5. Generate report
6. Verify risk scores

## Deliverables

### Week 1: MITRE Integration
- [ ] MITRE database populated
- [ ] Tool-to-technique mapping
- [ ] AI aware of MITRE context
- [ ] Coverage visualization API

### Week 2: Scheduled Jobs
- [ ] Cron scheduler running
- [ ] Scheduled job CRUD API
- [ ] Background worker
- [ ] Job execution working

### Week 3: Team Collaboration
- [ ] Workspaces created
- [ ] Comments on findings
- [ ] Activity feed
- [ ] Notifications

### Week 4: Enhanced Reporting
- [ ] Risk scoring implemented
- [ ] Executive summary
- [ ] PDF reports
- [ ] Trend analysis

## Success Metrics

1. **MITRE Coverage:** 80%+ of tools mapped to techniques
2. **Scheduled Jobs:** 99%+ execution reliability
3. **User Adoption:** 3+ users per workspace average
4. **Report Quality:** Executive-friendly, <5 min to generate

## Next Steps After Phase 1

Once Phase 1 is complete, proceed to Phase 2:
- Attack path visualization
- Safe simulation mode
- Security control validation
- Compliance reporting (PCI-DSS, SOC2)
