# TazoSploit v2

**Enterprise Multi-Tenant AI-Powered Penetration Testing Platform**

Built with security-first architecture: Control Plane / Execution Plane separation, full tenant isolation, comprehensive audit logging, and MITRE ATT&CK coverage.

**NEW:** Smart Features - Cron Scheduler & Skills Marketplace! 🚀

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

## Quick Startt

### Prerequisites
- Docker & Docker Compose
- LM Studio (for local LLM testing) with `gpt-oss-120b` model loaded
- 16GB+ RAM recommended

### 1. Setup Environment

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit--v2
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
tazosploit-saas-v2/
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
├── frontend/               # Next.js  frontend (to be added)
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

### Smart Features (New!)

TazoSploit v2 includes AI-driven smart features that transform pentesting:

- **Skills/Pentest Capabilities System**: Modular organization of pentest skills with tool integration and MITRE ATT&CK mappings
- **Persistent Memory & Threat Intelligence**: AI learns from engagements, tracks patterns, and provides recommendations
- **Multi-Agent Orchestration**: Parallel execution with specialized agents for comprehensive testing
- **Proactive Monitoring (Heartbeat)**: Continuous security monitoring, new service discovery, CVE checks, and alerting
- **MCP Server Integration**: Dynamic tool registration for extensibility without code changes
- **Natural Language Interface**: Conversational commands and responses for easy interaction

[See Smart Features Overview](docs/SMART_FEATURES_OVERVIEW.md) for details.

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

1. **Add Frontend**: Clone ixartz/-Boilerplate into `frontend/`
2. **Configure Clerk**: Set up authentication
3. **Deploy to K8s**: Use manifests in `kubernetes/`
4. **Add Monitoring**: Configure Prometheus/Grafana

## Documentation

### Smart Features Documentation
- [Smart Features Overview](docs/SMART_FEATURES_OVERVIEW.md) - High-level overview of all smart features
- [Implementation Guide](docs/IMPLEMENTATION_GUIDE.md) - Step-by-step implementation instructions
- [Skills System](docs/SKILLS_SYSTEM.md) - Modular pentest capabilities
- [Memory System](docs/MEMORY_SYSTEM.md) - Persistent learning and threat intelligence
- [Multi-Agent System](docs/MULTI_AGENT_SYSTEM.md) - Parallel execution and orchestration
- [Heartbeat System](docs/HEARTBEAT_SYSTEM.md) - Continuous monitoring and alerting
- [NLI System](docs/NLI_SYSTEM.md) - Natural language interface
- [MCP Integration](docs/MCP_INTEGRATION.md) - Dynamic tool registration

### Core Documentation
- [Architecture Details](docs/ARCHITECTURE.md)
- [Kali Tools List](docs/KALI_TOOLS.md)
- [Testing Guide](docs/TESTING_GUIDE.md)

## Security Considerations

This platform executes penetration testing tools. Ensure:
- Only authorized targets in approved scopes
- Proper authorization documentation
- Egress controls are configured
- Audit logs are retained
- Kill switch is tested

## License

MIT License

**Note**: This project was originally inspired by [CyberSecurityUP/TazoSploit](https://github.com/CyberSecurityUP/TazoSploit) but has been completely rewritten with a custom AI agent architecture.
