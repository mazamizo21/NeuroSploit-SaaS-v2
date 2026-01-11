# NeuroSploit SaaS v2 - Enterprise Architecture

## Executive Summary

NeuroSploit SaaS v2 is a multi-tenant, AI-powered penetration testing platform built with security-first principles. It separates the **Control Plane** (customer management) from the **Execution Plane** (pentest workers) to minimize blast radius and ensure tenant isolation.

---

## 1. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CONTROL PLANE                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                         Frontend (Next.js SaaS)                          │    │
│  │  • Tenant Onboarding    • Auth (Clerk + MFA)    • Dashboard              │    │
│  │  • Scope Management     • Billing/Quotas        • Audit Logs             │    │
│  │  • Policy Config        • Approvals             • Reports                │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                      │                                           │
│                                      ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                      Control Plane API (FastAPI)                         │    │
│  │  • Tenant Management    • Scope Validation      • Policy Engine          │    │
│  │  • Job Orchestration    • Quota Enforcement     • Audit Trail            │    │
│  │  • Kill Switch          • Authorization         • Rate Limiting          │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                      │                                           │
│                          ┌───────────┴───────────┐                              │
│                          ▼                       ▼                              │
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐              │
│  │      PostgreSQL             │  │         Redis               │              │
│  │  • Tenant Data (encrypted)  │  │  • Job Queue (namespaced)   │              │
│  │  • Scopes & Policies        │  │  • Rate Limit Counters      │              │
│  │  • Audit Logs               │  │  • Session Cache            │              │
│  │  • Per-tenant encryption    │  │  • Tenant-isolated queues   │              │
│  └─────────────────────────────┘  └─────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                            ┌──────────┴──────────┐
                            │   SECURITY BOUNDARY  │
                            │   (Network Isolation)│
                            └──────────┬──────────┘
                                       │
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             EXECUTION PLANE                                      │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    Job Scheduler / Orchestrator                          │    │
│  │  • Receives validated jobs from Control Plane                            │    │
│  │  • Enforces concurrency limits per tenant                                │    │
│  │  • Manages worker pool allocation                                        │    │
│  │  • Implements kill switch                                                │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                      │                                           │
│                    ┌─────────────────┼─────────────────┐                        │
│                    ▼                 ▼                 ▼                        │
│  ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐    │
│  │   Worker Pod 1       │ │   Worker Pod 2       │ │   Worker Pod N       │    │
│  │  ┌────────────────┐  │ │  ┌────────────────┐  │ │  ┌────────────────┐  │    │
│  │  │ Policy Engine  │  │ │  │ Policy Engine  │  │ │  │ Policy Engine  │  │    │
│  │  │ (Pre-execution)│  │ │  │ (Pre-execution)│  │ │  │ (Pre-execution)│  │    │
│  │  └───────┬────────┘  │ │  └───────┬────────┘  │ │  └───────┬────────┘  │    │
│  │          ▼           │ │          ▼           │ │          ▼           │    │
│  │  ┌────────────────┐  │ │  ┌────────────────┐  │ │  ┌────────────────┐  │    │
│  │  │Open Interpreter│  │ │  │Open Interpreter│  │ │  │Open Interpreter│  │    │
│  │  │ + LM Studio    │  │ │  │ + LM Studio    │  │ │  │ + Claude API   │  │    │
│  │  │ (Dev/Test)     │  │ │  │ (Dev/Test)     │  │ │  │ (Production)   │  │    │
│  │  └───────┬────────┘  │ │  └───────┬────────┘  │ │  └───────┬────────┘  │    │
│  │          ▼           │ │          ▼           │ │          ▼           │    │
│  │  ┌────────────────┐  │ │  ┌────────────────┐  │ │  ┌────────────────┐  │    │
│  │  │  Kali Linux    │  │ │  │  Kali Linux    │  │ │  │  Kali Linux    │  │    │
│  │  │  150+ Tools    │  │ │  │  150+ Tools    │  │ │  │  150+ Tools    │  │    │
│  │  │  (Ephemeral)   │  │ │  │  (Ephemeral)   │  │ │  │  (Ephemeral)   │  │    │
│  │  └────────────────┘  │ │  └────────────────┘  │ │  └────────────────┘  │    │
│  │  Egress: ALLOWLIST   │ │  Egress: ALLOWLIST   │ │  Egress: ALLOWLIST   │    │
│  └──────────────────────┘ └──────────────────────┘ └──────────────────────┘    │
│                                      │                                           │
│                                      ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                      Results Store (Encrypted)                           │    │
│  │  • Per-tenant encryption keys     • Retention policies                   │    │
│  │  • Export/Delete on demand        • Evidence chain                       │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Tenant Isolation Model (5 Layers)

### 2.1 Identity Isolation
- Every API request carries tenant context (JWT with tenant_id claim)
- Server-side enforcement - NEVER trust client-provided tenant_id
- Clerk handles auth with MFA, social login, passkeys
- Role-based access: Admin, Operator, Viewer, Auditor

### 2.2 Data Isolation
- **Model**: Hybrid (shared DB, tenant-scoped tables with RLS)
- **Encryption**: Per-tenant encryption keys (AWS KMS / HashiCorp Vault)
- **Retention**: Configurable per tenant, auto-delete after X days
- **Export**: Customer-controlled data export (GDPR compliance)

### 2.3 Compute Isolation
- Workers run in ephemeral containers (destroyed after job)
- Premium tier: Dedicated worker pool per tenant
- Job timeout enforcement (max 4 hours default)
- Resource limits: CPU, memory, disk per container

### 2.4 Network Isolation
- Workers have NO default internet access
- Egress allowlist per job (only approved targets)
- Predictable egress IPs for customer allowlisting
- VPC peering for enterprise customers

### 2.5 Queue/Cache Isolation
- Redis namespaces per tenant: `tenant:{id}:queue`
- No cross-tenant data leakage in cache
- Tenant-aware authorization on all queue operations

---

## 3. MITRE ATT&CK Coverage

The AI agent executes full attack lifecycle with configurable phases:

```
┌─────────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK PHASES                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. RECONNAISSANCE (TA0043)                                     │
│     ├── Active Scanning (T1595)                                 │
│     │   └── nmap, masscan, zmap                                 │
│     ├── Search Open Websites (T1593)                            │
│     │   └── subfinder, amass, theHarvester                      │
│     ├── Gather Victim Network Info (T1590)                      │
│     │   └── dnsrecon, dnsenum, whois                            │
│     └── Search Open Technical DBs (T1596)                       │
│         └── shodan, censys, searchsploit                        │
│                                                                 │
│  2. RESOURCE DEVELOPMENT (TA0042)                               │
│     ├── Develop Capabilities (T1587)                            │
│     │   └── msfvenom, custom exploits                           │
│     └── Obtain Capabilities (T1588)                             │
│         └── exploit-db, metasploit modules                      │
│                                                                 │
│  3. INITIAL ACCESS (TA0001)                                     │
│     ├── Exploit Public-Facing App (T1190)                       │
│     │   └── sqlmap, nikto, nuclei, burp                         │
│     ├── External Remote Services (T1133)                        │
│     │   └── hydra, medusa, crowbar                              │
│     └── Valid Accounts (T1078)                                  │
│         └── credential stuffing, spray attacks                  │
│                                                                 │
│  4. EXECUTION (TA0002)                                          │
│     ├── Command and Scripting (T1059)                           │
│     │   └── reverse shells, web shells                          │
│     └── Exploitation for Client Execution (T1203)               │
│         └── metasploit, custom payloads                         │
│                                                                 │
│  5. PERSISTENCE (TA0003)                                        │
│     ├── Account Manipulation (T1098)                            │
│     ├── Create Account (T1136)                                  │
│     ├── Scheduled Task/Job (T1053)                              │
│     └── Boot/Logon Autostart (T1547)                            │
│                                                                 │
│  6. PRIVILEGE ESCALATION (TA0004)                               │
│     ├── Exploitation for Privilege Escalation (T1068)           │
│     │   └── linpeas, winpeas, linux-exploit-suggester           │
│     ├── Valid Accounts (T1078)                                  │
│     └── Sudo/Sudoers (T1548.003)                                │
│                                                                 │
│  7. DEFENSE EVASION (TA0005)                                    │
│     ├── Obfuscated Files (T1027)                                │
│     ├── Indicator Removal (T1070)                               │
│     └── Masquerading (T1036)                                    │
│                                                                 │
│  8. CREDENTIAL ACCESS (TA0006)                                  │
│     ├── Brute Force (T1110)                                     │
│     │   └── hydra, john, hashcat                                │
│     ├── OS Credential Dumping (T1003)                           │
│     │   └── mimikatz, secretsdump                               │
│     └── Credentials from Password Stores (T1555)                │
│                                                                 │
│  9. DISCOVERY (TA0007)                                          │
│     ├── Network Service Discovery (T1046)                       │
│     │   └── nmap service scan                                   │
│     ├── System Information Discovery (T1082)                    │
│     └── Account Discovery (T1087)                               │
│                                                                 │
│  10. LATERAL MOVEMENT (TA0008)                                  │
│      ├── Remote Services (T1021)                                │
│      │   └── psexec, smbexec, wmiexec, evil-winrm               │
│      ├── Exploitation of Remote Services (T1210)                │
│      └── Pass the Hash/Ticket (T1550)                           │
│          └── impacket suite                                     │
│                                                                 │
│  11. COLLECTION (TA0009)                                        │
│      ├── Data from Local System (T1005)                         │
│      └── Data Staged (T1074)                                    │
│                                                                 │
│  12. EXFILTRATION (TA0010)                                      │
│      └── Exfiltration Over C2 Channel (T1041)                   │
│                                                                 │
│  13. IMPACT (TA0040) - REPORTING ONLY                           │
│      └── Document potential impact, no destructive actions      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Policy Engine

The Policy Engine sits between the AI agent and tool execution:

```python
class PolicyEngine:
    """
    Enforces security policies before any tool execution.
    Default: DENY unless explicitly allowed.
    """
    
    def validate_action(self, action: Action, context: JobContext) -> PolicyDecision:
        checks = [
            self.check_tool_allowed(action.tool, context.policy),
            self.check_target_in_scope(action.target, context.approved_scope),
            self.check_intensity_limit(action.intensity, context.max_intensity),
            self.check_rate_limit(context.tenant_id, action.tool),
            self.check_time_window(context.allowed_hours),
            self.check_job_budget(context.remaining_budget),
        ]
        
        if not all(checks):
            return PolicyDecision.DENY
        
        # Log decision for audit
        self.audit_log(action, context, PolicyDecision.ALLOW)
        return PolicyDecision.ALLOW
```

### Policy Levels
1. **Global**: Platform-wide restrictions (no destructive actions)
2. **Tenant**: Tenant-specific tool allowlist
3. **Job**: Per-job scope and intensity limits
4. **Real-time**: Rate limits, budget enforcement

---

## 5. Observability & Debugging

### 5.1 Full Transaction Logging

Every operation is logged with:

```json
{
  "transaction_id": "uuid",
  "timestamp": "2026-01-11T16:43:00Z",
  "tenant_id": "tenant_123",
  "job_id": "job_456",
  "phase": "RECONNAISSANCE",
  "action": {
    "type": "TOOL_EXECUTION",
    "tool": "nmap",
    "command": "nmap -sV -sC 192.168.1.0/24",
    "parameters": {"target": "192.168.1.0/24", "options": "-sV -sC"}
  },
  "policy_decision": {
    "allowed": true,
    "checks_passed": ["tool_allowed", "target_in_scope", "rate_limit_ok"],
    "policy_version": "v1.2.3"
  },
  "execution": {
    "start_time": "2026-01-11T16:43:01Z",
    "end_time": "2026-01-11T16:45:30Z",
    "exit_code": 0,
    "stdout_lines": 1542,
    "stderr_lines": 0
  },
  "llm_interaction": {
    "model": "openai/gpt-oss-120b",
    "prompt_tokens": 2341,
    "completion_tokens": 892,
    "total_tokens": 3233,
    "cost_usd": 0.0032,
    "latency_ms": 2341
  },
  "output": {
    "summary": "Discovered 12 hosts, 47 open ports",
    "findings": 3,
    "artifacts_stored": ["nmap_scan_001.xml"]
  }
}
```

### 5.2 LLM Message Logging

```json
{
  "llm_session_id": "session_789",
  "messages": [
    {
      "role": "system",
      "content": "You are a penetration testing agent...",
      "tokens": 450
    },
    {
      "role": "user", 
      "content": "Scan target 192.168.1.0/24 for open ports",
      "tokens": 12
    },
    {
      "role": "assistant",
      "content": "I'll perform an nmap scan...",
      "tokens": 156,
      "tool_calls": [{"name": "execute_command", "args": {...}}]
    }
  ],
  "total_cost": 0.0032,
  "model_config": {
    "temperature": 0.1,
    "max_tokens": 4096
  }
}
```

### 5.3 Real-time Metrics

- **Per-tenant**: Jobs running, API calls, token usage, costs
- **Per-worker**: CPU, memory, network, job duration
- **Per-job**: Progress, findings, errors, phase completion
- **Platform**: Total jobs, success rate, error rate

---

## 6. API Security

### 6.1 Authentication Flow

```
Client → API Gateway → Auth Middleware → Rate Limiter → Handler
           │              │                  │
           ▼              ▼                  ▼
        Clerk JWT    Tenant Context    Redis Counter
        Validation   Extraction        Check
```

### 6.2 Authorization Model

```python
# Object-Level Authorization
@require_permission("jobs:create")
@require_scope_ownership  # User must own the target scope
async def create_job(tenant_id: str, scope_id: str, job_config: JobConfig):
    # Verify scope belongs to tenant
    scope = await get_scope(scope_id)
    if scope.tenant_id != tenant_id:
        raise ForbiddenError("Scope not owned by tenant")
    
    # Verify targets are within approved scope
    for target in job_config.targets:
        if not scope.contains(target):
            raise ForbiddenError(f"Target {target} not in approved scope")
    
    # Create job with full audit trail
    return await create_job_with_audit(tenant_id, scope_id, job_config)
```

### 6.3 Rate Limiting

| Tier | API Calls/min | Jobs/hour | Concurrent Jobs |
|------|--------------|-----------|-----------------|
| Free | 60 | 5 | 1 |
| Pro | 300 | 50 | 5 |
| Enterprise | 1000 | Unlimited | 20 |

---

## 7. Infrastructure & Scaling

### 7.1 Kubernetes Deployment

```yaml
# Worker Pod Security Policy
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: neurosploit-worker
spec:
  privileged: false
  runAsUser:
    rule: MustRunAsNonRoot
  seLinux:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
    - 'emptyDir'
    - 'secret'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
```

### 7.2 Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: worker-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: neurosploit-worker
  minReplicas: 2
  maxReplicas: 100
  metrics:
    - type: External
      external:
        metric:
          name: redis_queue_length
          selector:
            matchLabels:
              queue: pentest-jobs
        target:
          type: AverageValue
          averageValue: 5
```

---

## 8. Project Structure

```
neurosploit-saas-v2/
├── docker-compose.yml              # Local development
├── docker-compose.prod.yml         # Production overrides
├── kubernetes/                     # K8s manifests
│   ├── control-plane/
│   ├── execution-plane/
│   └── monitoring/
│
├── frontend/                       # Next.js SaaS (ixartz/SaaS-Boilerplate)
│   ├── src/
│   │   ├── app/                    # App Router pages
│   │   ├── components/             # React components
│   │   └── lib/                    # Utilities
│   └── Dockerfile
│
├── control-plane/                  # Control Plane API
│   ├── api/
│   │   ├── routers/
│   │   │   ├── tenants.py
│   │   │   ├── scopes.py
│   │   │   ├── jobs.py
│   │   │   ├── policies.py
│   │   │   └── audit.py
│   │   ├── auth.py
│   │   ├── models.py
│   │   └── database.py
│   ├── services/
│   │   ├── policy_engine.py
│   │   ├── quota_manager.py
│   │   └── kill_switch.py
│   └── Dockerfile
│
├── execution-plane/                # Execution Plane
│   ├── scheduler/
│   │   ├── job_scheduler.py
│   │   └── worker_manager.py
│   ├── worker/
│   │   ├── main.py
│   │   ├── agent_executor.py
│   │   └── tool_runner.py
│   └── Dockerfile
│
├── neurosploit-core/               # Fresh clone of CyberSecurityUP/NeuroSploit
│   ├── core/
│   │   ├── agents/                 # Original + custom agents
│   │   ├── tools/
│   │   └── prompts/
│   └── ...
│
├── kali-executor/                  # Kali container with tools
│   ├── Dockerfile
│   ├── tools/                      # 150+ tool configs
│   └── open-interpreter/
│
├── observability/
│   ├── logging/
│   ├── metrics/
│   └── tracing/
│
└── docs/
    ├── ARCHITECTURE.md             # This file
    ├── SECURITY.md
    ├── API.md
    └── DEPLOYMENT.md
```

---

## 9. Technology Stack

| Component | Technology | Reason |
|-----------|------------|--------|
| **Frontend** | Next.js 14 + Tailwind + Shadcn | ixartz/SaaS-Boilerplate, production-ready |
| **Auth** | Clerk | MFA, social, passkeys, multi-tenant |
| **Control Plane API** | FastAPI | Async, OpenAPI, Python ecosystem |
| **Execution Scheduler** | Celery + Redis | Reliable job queue, rate limiting |
| **Database** | PostgreSQL | RLS, JSON, full-text search |
| **Cache/Queue** | Redis | Pub/sub, rate limiting, sessions |
| **AI Tool** | Open Interpreter | HTTP API, local LLM support, shell exec |
| **LLM (Dev)** | LM Studio + gpt-oss-120b | Local, no API costs |
| **LLM (Prod)** | Claude API | Best reasoning, tool use |
| **Container Runtime** | Docker / Kubernetes | Isolation, scaling |
| **Secrets** | HashiCorp Vault | Per-tenant encryption keys |
| **Observability** | OpenTelemetry + Grafana | Traces, metrics, logs |

---

## 10. Security Checklist

- [ ] Tenant isolation at all 5 layers
- [ ] Per-tenant encryption keys
- [ ] Policy engine between AI and tools
- [ ] Egress allowlist per job
- [ ] Rate limiting per tenant
- [ ] Kill switch (global + tenant + job)
- [ ] Full audit logging
- [ ] Signed container images (SLSA)
- [ ] No shell injection vulnerabilities
- [ ] Input validation on all endpoints
- [ ] OWASP ASVS compliance
- [ ] SOC 2 Type II preparation

---

## 11. Implementation Phases

### Phase 1: Foundation (Week 1-2)
- Project setup and structure
- Fresh NeuroSploit clone
- SaaS Boilerplate integration
- Basic Docker compose

### Phase 2: Control Plane (Week 3-4)
- Tenant management
- Scope/policy management
- Job orchestration
- Audit logging

### Phase 3: Execution Plane (Week 5-6)
- Kali container with 150+ tools
- Open Interpreter integration
- Policy engine
- Worker pool

### Phase 4: Observability (Week 7-8)
- Full transaction logging
- LLM message logging
- Metrics dashboard
- Cost tracking

### Phase 5: Production Hardening (Week 9-10)
- Security hardening
- Kubernetes deployment
- Performance testing
- Compliance documentation
