# TazoSploit: COMPREHENSIVE DOCKER SETUP GUIDE
**Date:** 2025-01-28
**Purpose:** One-click installation, end-to-end, no errors

---

## 🐳 One-Click Installation

### Quick Start (All Services + Vulnerable Lab)

```bash
# Clone or navigate to TazoSploit directory
cd /path/to/TazoSploit

# Run one-click setup (everything included)
./setup-docker.sh

# Or manually:
docker-compose -f docker-compose-all.yml up -d
```

---

## 📦 What's Included

### 1. TazoSploit Core Services
- ✅ Control Plane API (tenant management, auth, orchestration)
- ✅ Job Scheduler (cron, interval, one-time jobs)
- ✅ Worker Pool (multi-instance, scalable)
- ✅ PostgreSQL Database (persistent)
- ✅ Redis Queue (job management)
- ✅ Grafana Dashboard (monitoring)
- ✅ Prometheus Metrics (observability)

### 2. Smart Features (All 6 Systems)
- ✅ Skills System (6 complete skills, 50+ tools)
- ✅ Memory System (enhanced, learning, threat intelligence)
- ✅ Multi-Agent Orchestration (4 specialized agents)
- ✅ Heartbeat System (continuous monitoring)
- ✅ MCP Integration (dynamic tool loading)
- ✅ Natural Language Interface (10 intents)

### 3. Pentest Tools (Pre-installed)
- ✅ Nmap, Masscan, RustScan
- ✅ Nuclei, Nikto, Gobuster
- ✅ SQLMap, XSStrike, WhatWeb
- ✅ Metasploit Framework
- ✅ Hydra, John, Hashcat
- ✅ LinPEAS, WinPEAS
- ✅ Mimikatz, LaZagne
- ✅ CrackMapExec, Impacket
- ✅ Plus 100+ more tools

### 4. Vulnerable Lab (Enterprise-Grade)
- ✅ 8 Web Applications (DVWA, DVNA, Juice Shop, etc.)
- ✅ 6 Databases (MySQL, PostgreSQL, MongoDB, Redis, etc.)
- ✅ Load Balancer (HAProxy)
- ✅ File Server (Samba)
- ✅ Jump Host (SSH)
- ✅ Admin Panel
- ✅ Monitoring (Elasticsearch, Kibana)
- ✅ 4 Isolated Networks (External, DMZ, Internal, Database)

### 5. Documentation (Complete)
- ✅ All 8 smart features guides (93,000+ words)
- ✅ Architecture documentation
- ✅ Implementation guides
- ✅ Testing guides
- ✅ API documentation

### 6. Configuration (All Included)
- ✅ Environment variables (pre-configured for dev)
- ✅ Database schemas (auto-initialized)
- ✅ Skill definitions (6 complete skills)
- ✅ Tool configurations (all tools ready)
- ✅ Network isolation (security boundaries)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HOST MACHINE                          │
└─────────────────────────────────────────────────────────────┘
                             │
        ┌──────────────────────┴──────────────────────┐
        │                                            │
        ▼                                            ▼
┌──────────────────┐                    ┌──────────────────┐
│  TazoSploit     │                    │  Vulnerable Lab  │
│  Services       │                    │  (Test Target)   │
└──────────────────┘                    └──────────────────┘
        │                                            │
        │                                            │
        ▼                                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    DOCKER NETWORKS                      │
│  - control-plane-network                                  │
│  - execution-plane-network                               │
│  - kali-network                                          │
│  - lab_external                                          │
│  - lab_dmz                                              │
│  - lab_internal                                          │
│  - lab_database                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Setup Steps (One-Click)

### Step 1: Prerequisites

```bash
# Check Docker installed
docker --version

# Check Docker Compose installed
docker-compose --version

# If not installed:
# macOS: Download Docker Desktop
# Linux: curl -fsSL https://get.docker.com | sh
```

### Step 2: One-Click Setup

```bash
# Navigate to TazoSploit directory
cd /Users/tazjack/Documents/PenTest/TazoSploit

# Run setup script (does everything)
chmod +x setup-docker.sh
./setup-docker.sh

# Wait for all services to start (2-3 minutes)
```

### Step 3: Verify Everything Works

```bash
# Check all containers are running
docker ps

# Should see:
# - tazosploit-control-api
# - tazosploit-scheduler
# - tazosploit-worker (x2)
# - tazosploit-kali-executor (x3)
# - tazosploit-postgres
# - tazosploit-redis
# - tazosploit-grafana
# - tazosploit-prometheus
# - lab-dvwa, lab-dvna, lab-juice-shop, etc.
# - lab-firewall, lab-haproxy, etc.
# - lab-mysql, lab-postgres, lab-mongodb, etc.

# Check TazoSploit API
curl http://localhost:8000/health

# Access Grafana Dashboard
# URL: http://localhost:3001
# User: admin
# Password: admin (change in production)

# Access Vulnerable Lab Applications
# DVWA: http://localhost:8081
# DVNA: http://localhost:9091
# Juice Shop: http://localhost:3000
# HAProxy Stats: http://localhost:8404 (no auth)
```

### Step 4: Run First Test

```bash
# Test pentest against DVWA
curl -X POST http://localhost:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://lab-dvwa:80",
    "objective": "Perform full reconnaissance and identify vulnerabilities",
    "max_iterations": 10
  }'

# Check job status
curl http://localhost:8000/api/v1/jobs

# View results
curl http://localhost:8000/api/v1/jobs/{job_id}/results
```

---

## 📁 Docker Compose Files

### docker-compose-all.yml (One-Click)
- Includes TazoSploit services
- Includes vulnerable lab
- All networks configured
- All volumes configured
- **Run this for complete setup**

### docker-compose.yml (TazoSploit Only)
- TazoSploit services only
- Control plane + execution plane
- Infrastructure (postgres, redis)
- Observability (grafana, prometheus)

### docker-compose.infra.yml (Infrastructure Only)
- Postgres, Redis, Grafana, Prometheus
- For production deployments

### vulnerable-lab/docker-compose.enterprise.yml (Lab Only)
- Vulnerable applications only
- For external testing

---

## 🔧 Configuration

### Environment Variables (.env)

```bash
# Database Configuration
DB_PASSWORD=tazosploit_dev

# TazoSploit Configuration
SECRET_KEY=dev-secret-change-in-production
ENVIRONMENT=development
LOG_LEVEL=DEBUG

# LLM Configuration
LLM_PROVIDER=lm-studio
LLM_API_BASE=http://host.docker.internal:1234/v1
LLM_MODEL=openai/gpt-oss-120b

# OpenAI (Optional)
OPENAI_API_KEY=your-openai-api-key

# Anthropic (Optional)
ANTHROPIC_API_KEY=your-anthropic-api-key

# Job Configuration
MAX_CONCURRENT_JOBS=10

# Grafana Configuration
GRAFANA_PASSWORD=admin
```

### Port Mappings

| Port | Service | Access |
|------|----------|---------|
| 8000 | TazoSploit API | HTTP |
| 5432 | PostgreSQL | Direct DB access |
| 6379 | Redis | Direct queue access |
| 3001 | Grafana Dashboard | Web UI |
| 9090 | Prometheus Metrics | Web UI |
| 8081 | DVWA (Lab) | Vulnerable App |
| 9091 | DVNA (Lab) | Vulnerable App |
| 3000 | Juice Shop (Lab) | Vulnerable App |
| 8404 | HAProxy Stats (Lab) | Monitoring |

---

## 🧪 Testing

### Test 1: Health Check
```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy", "version": "2.0.0"}
```

### Test 2: Create Pentest Job
```bash
curl -X POST http://localhost:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://lab-dvwa:80",
    "objective": "Full reconnaissance",
    "max_iterations": 5
  }'
# Expected: {"job_id": "...", "status": "queued"}
```

### Test 3: Get Job Status
```bash
curl http://localhost:8000/api/v1/jobs
# Expected: List of all jobs with status
```

### Test 4: Get Job Results
```bash
curl http://localhost:8000/api/v1/jobs/{job_id}/results
# Expected: JSON with findings, vulnerabilities, etc.
```

### Test 5: Natural Language Interface
```bash
curl -X POST http://localhost:8000/api/v1/nli/parse \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Scan 192.168.1.50 for open ports"
  }'
# Expected: {"intent": "SCAN", "target": "192.168.1.50", "parameters": {...}}
```

---

## 📊 Monitoring

### Grafana Dashboard
- URL: http://localhost:3001
- Credentials: admin / admin
- Pre-configured dashboards:
  - TazoSploit Overview
  - Job Performance
  - Worker Pool Status
  - Vulnerabilities Found

### Prometheus Metrics
- URL: http://localhost:9090
- Metrics available:
  - `tazosploit_jobs_total`
  - `tazosploit_jobs_completed`
  - `tazosploit_jobs_failed`
  - `tazosploit_workers_active`
  - `tazosploit_vulnerabilities_found`

### Logs
```bash
# View TazoSploit logs
docker logs -f tazosploit-control-api

# View worker logs
docker logs -f tazosploit-worker

# View scheduler logs
docker logs -f tazosploit-scheduler

# View all logs
docker-compose -f docker-compose-all.yml logs -f
```

---

## 🧹 Cleanup

### Stop All Services
```bash
# Stop and remove all containers
docker-compose -f docker-compose-all.yml down

# Remove volumes (deletes all data)
docker-compose -f docker-compose-all.yml down -v

# Remove networks
docker network prune -f
```

### Reset Everything (Clean Slate)
```bash
# Stop, remove volumes, remove images
docker-compose -f docker-compose-all.yml down -v --rmi all

# Rebuild from scratch
docker-compose -f docker-compose-all.yml build --no-cache
docker-compose -f docker-compose-all.yml up -d
```

---

## 🐛 Troubleshooting

### Issue: Container won't start
```bash
# Check logs
docker logs tazosploit-control-api

# Check container status
docker ps -a

# Restart specific container
docker restart tazosploit-control-api
```

### Issue: Can't access TazoSploit API
```bash
# Check if API is running
curl http://localhost:8000/health

# Check if port is exposed
docker port tazosploit-control-api

# Check network connectivity
docker network inspect tazosploit-control
```

### Issue: Worker can't connect to control plane
```bash
# Check control plane is healthy
curl http://localhost:8000/health

# Check worker can reach control plane
docker exec tazosploit-worker ping control-plane-api

# Check environment variables
docker exec tazosploit-worker env | grep CONTROL_PLANE
```

### Issue: Kali executor can't reach vulnerable lab
```bash
# Check networks are connected
docker network inspect kali-network
docker network inspect lab_dmz

# Check container has correct network
docker inspect tazosploit-kali-executor | grep Networks

# Restart containers
docker-compose -f docker-compose-all.yml restart
```

### Issue: Database connection failed
```bash
# Check postgres is running
docker ps | grep postgres

# Check postgres health
docker exec tazosploit-postgres pg_isready -U tazosploit

# Check database exists
docker exec tazosploit-postgres psql -U tazosploit -l

# Check init script ran
docker exec tazosploit-postgres psql -U tazosploit -d tazosploit -c "\dt"
```

---

## 📋 Pre-Flight Checklist

Before running docker-compose, verify:

- [ ] Docker installed and running
- [ ] Docker Compose installed
- [ ] 8GB+ RAM available
- [ ] 50GB+ disk space available
- [ ] Ports 8000, 5432, 6379, 3001, 9090 available
- [ ] No firewall blocking Docker
- [ ] .env file configured (copy from .env.example)
- [ ] Internet access (for downloading images)

---

## 🎯 Success Criteria

### One-Click Installation Works If:
- [ ] `./setup-docker.sh` runs without errors
- [ ] All containers start successfully
- [ ] TazoSploit API responds to health check
- [ ] Grafana dashboard is accessible
- [ ] Vulnerable lab applications are accessible
- [ ] Can create and run pentest job
- [ ] Can view job results
- [ ] Natural language interface works

---

## 📚 Next Steps

After successful installation:

1. **I Will Test Everything Autonomously (NO ASKING PERMISSION):**
   - Test ALL smart features against vulnerable lab
   - Test each of 6 skills
   - Test NLI interface
   - Test multi-agent orchestration
   - Test ALL evasion techniques
   - Continue testing until product is perfect
   - Document all test results with evidence

2. **Read Documentation:** Check `/docs/` for detailed guides
3. **Handle All Testing Myself** - No asking for permission to test

---

## 🚀 Production Deployment

For production deployment:

1. **Update Environment Variables:**
   ```bash
   ENVIRONMENT=production
   SECRET_KEY=<strong-random-string>
   DB_PASSWORD=<strong-random-string>
   LOG_LEVEL=INFO
   GRAFANA_PASSWORD=<strong-password>
   ```

2. **Use Infrastructure Only:**
   ```bash
   docker-compose -f docker-compose.infra.yml up -d
   ```

3. **Disable Development Services:**
   ```bash
   # Don't deploy vulnerable lab in production
   # Don't use LM Studio, use production API
   ```

4. **Enable HTTPS:**
   ```bash
   # Configure reverse proxy (nginx/traefik)
   # Use SSL certificates (Let's Encrypt)
   ```

---

*Last Updated: 2025-01-28*
*One-Click Docker Setup - End-to-End, No Errors*
