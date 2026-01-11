# NeuroSploit SaaS v2

**Enterprise Multi-Tenant AI-Powered Penetration Testing Platform**

Built with security-first architecture: Control Plane / Execution Plane separation, full tenant isolation, comprehensive audit logging, and MITRE ATT&CK coverage.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      CONTROL PLANE                          │
│  Frontend (Next.js) → API (FastAPI) → PostgreSQL/Redis     │
│  • Tenant Management  • Job Orchestration  • Audit Logs    │
└─────────────────────────────────────────────────────────────┘
                              │
                    [Security Boundary]
                              │
┌─────────────────────────────────────────────────────────────┐
│                     EXECUTION PLANE                         │
│  Scheduler → Workers → Kali Containers (Open Interpreter)  │
│  • Policy Engine  • 150+ Tools  • Full Transaction Logging │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker & Docker Compose
- LM Studio (for local LLM testing) with `gpt-oss-120b` model loaded
- 16GB+ RAM recommended

### 1. Setup Environment

```bash
cd /Users/tazjack/Documents/PenTest/NeuroSploit-SaaS-v2
cp .env.example .env
# Edit .env with your configuration
```

### 2. Start LM Studio
1. Open LM Studio
2. Load `openai/gpt-oss-120b` model
3. Start the server on port 1234

### 3. Start Services

```bash
docker-compose up -d
```

### 4. Verify Deployment

```bash
# Check all services
docker-compose ps

# Test API health
curl http://localhost:8000/health
```

## Project Structure

```
neurosploit-saas-v2/
├── control-plane/          # Control Plane API
│   ├── api/
│   │   ├── routers/        # API endpoints
│   │   ├── models.py       # Database models
│   │   ├── auth.py         # JWT authentication
│   │   └── database.py     # PostgreSQL config
│   └── services/           # Business logic
│
├── execution-plane/        # Execution Plane
│   ├── scheduler/          # Job scheduler
│   └── worker/             # Job workers
│
├── kali-executor/          # Kali Linux container
│   ├── Dockerfile          # 150+ pentest tools
│   └── open-interpreter/   # AI agent (dynamic_agent.py, exploit_executor.py)
│
├── frontend/               # Next.js SaaS frontend (to be added)
│
├── observability/          # Logging, metrics, tracing
│
├── kubernetes/             # K8s deployment manifests
│
└── docs/
    ├── ARCHITECTURE.md     # Detailed architecture
    └── KALI_TOOLS.md       # 150+ tool documentation
```

## Key Features

### Security (5-Layer Tenant Isolation)
- **Identity**: JWT with tenant context, server-side enforcement
- **Data**: Per-tenant encryption, RLS in PostgreSQL
- **Compute**: Ephemeral containers, resource limits
- **Network**: Egress allowlist per job, no default internet
- **Queue**: Namespaced Redis queues, tenant-aware auth

### MITRE ATT&CK Coverage
- Reconnaissance (T1595, T1593, T1590, T1596)
- Vulnerability Scanning
- Initial Access (T1190, T1133, T1078)
- Execution (T1059, T1203)
- Persistence (T1098, T1136, T1053)
- Privilege Escalation (T1068, T1548)
- Lateral Movement (T1021, T1210, T1550)
- Collection & Reporting

### Full Observability
- Every LLM interaction logged (tokens, cost, messages)
- Every command execution logged (input, output, duration)
- Full audit trail (who, what, when, why)
- Real-time metrics dashboard (Grafana)

### Policy Engine
- Tool allowlist/blocklist per tenant
- Target scope enforcement
- Intensity limits
- Rate limiting
- Kill switch (global, tenant, job level)

## API Endpoints

### Health
- `GET /health` - Basic health check
- `GET /health/detailed` - Dependency status

### Tenants
- `GET /api/v1/tenants/me` - Current tenant info

### Scopes (Target Authorization)
- `GET /api/v1/scopes` - List approved scopes
- `POST /api/v1/scopes` - Create new scope

### Jobs
- `GET /api/v1/jobs` - List jobs
- `POST /api/v1/jobs` - Create job
- `GET /api/v1/jobs/{id}` - Job details
- `POST /api/v1/jobs/{id}/cancel` - Cancel job (kill switch)
- `GET /api/v1/jobs/{id}/logs` - Job logs

### Policies
- `GET /api/v1/policies` - List policies

### Audit
- `GET /api/v1/audit` - Audit logs

## LLM Configuration

### Development (LM Studio)
```env
LLM_PROVIDER=lm-studio
LLM_API_BASE=http://host.docker.internal:1234/v1
LLM_MODEL=openai/gpt-oss-120b
```

### Production (Claude API)
```env
LLM_PROVIDER=claude
ANTHROPIC_API_KEY=your-key
```

## Next Steps

1. **Add Frontend**: Clone ixartz/SaaS-Boilerplate into `frontend/`
2. **Configure Clerk**: Set up authentication
3. **Deploy to K8s**: Use manifests in `kubernetes/`
4. **Add Monitoring**: Configure Prometheus/Grafana

## Documentation

- [Architecture Details](docs/ARCHITECTURE.md)
- [Kali Tools List](docs/KALI_TOOLS.md)

## Security Considerations

This platform executes penetration testing tools. Ensure:
- Only authorized targets in approved scopes
- Proper authorization documentation
- Egress controls are configured
- Audit logs are retained
- Kill switch is tested

## License

MIT License

**Note**: This project was originally inspired by [CyberSecurityUP/NeuroSploit](https://github.com/CyberSecurityUP/NeuroSploit) but has been completely rewritten with a custom AI agent architecture.
