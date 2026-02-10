#!/bin/bash
# TazoSploit: One-Click Docker Setup Script
# Sets up everything: TazoSploit services + Smart Features + Vulnerable Lab
# End-to-end, no errors

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKER_COMPOSE_FILE="docker-compose-all.yml"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  TazoSploit: One-Click Docker Setup${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# =============================================================================
# STEP 1: Check Prerequisites
# =============================================================================

echo -e "${YELLOW}[1/8] Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker is not installed${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker is installed${NC}"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose is not installed${NC}"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose is installed${NC}"

# Check RAM
TOTAL_RAM=$(sysctl -n hw.memtotal 2>/dev/null || echo 0)
TOTAL_RAM_GB=$((TOTAL_RAM / 1024 / 1024 / 1024))
if [ "$TOTAL_RAM_GB" -lt 8 ]; then
    echo -e "${YELLOW}⚠ Warning: Less than 8GB RAM detected${NC}"
    echo "TazoSploit requires at least 8GB RAM for optimal performance"
else
    echo -e "${GREEN}✓ RAM: ${TOTAL_RAM_GB}GB${NC}"
fi

# Check disk space
DISK_SPACE=$(df -h "$PROJECT_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
echo -e "${GREEN}✓ Disk Space: ${DISK_SPACE}B available${NC}"

# Navigate to project directory
cd "$PROJECT_DIR"

echo ""

# =============================================================================
# STEP 2: Create Required Directories
# =============================================================================

echo -e "${YELLOW}[2/8] Creating required directories...${NC}"

mkdir -p logs
mkdir -p data
mkdir -p data/jobs
mkdir -p data/evidence
mkdir -p data/targets
mkdir -p data/memory/TARGET_KNOWLEDGE
mkdir -p data/memory/SESSION_HISTORY
mkdir -p vulnerable-lab/config
mkdir -p vulnerable-lab/data/mysql
mkdir -p vulnerable-lab/data/samba/shared
mkdir -p vulnerable-lab/data/samba/confidential
mkdir -p vulnerable-lab/admin-panel/uploads
mkdir -p config/grafana/provisioning
mkdir -p config/prometheus

echo -e "${GREEN}✓ Directories created${NC}"
echo ""

# =============================================================================
# STEP 3: Create Configuration Files
# =============================================================================

echo -e "${YELLOW}[3/8] Creating configuration files...${NC}"

# Create .env if not exists
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo -e "${GREEN}✓ Created .env from .env.example${NC}"
    else
        cat > .env << 'EOF'
# TazoSploit Configuration
ENVIRONMENT=development
SECRET_KEY=dev-secret-change-in-production
LOG_LEVEL=DEBUG

# Database Configuration
DB_PASSWORD=tazosploit_dev

# LLM Configuration
LLM_PROVIDER=lm-studio
LLM_API_BASE=http://host.docker.internal:1234/v1
LLM_MODEL=openai/gpt-oss-120b

# Optional API Keys
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# Job Configuration
MAX_CONCURRENT_JOBS=10

# Grafana Configuration
GRAFANA_PASSWORD=admin
EOF
        echo -e "${GREEN}✓ Created .env file${NC}"
    fi
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

# Create HAProxy config
cat > vulnerable-lab/config/haproxy.cfg << 'EOF'
global
    log stdout format raw local0
    stats socket /var/run/haproxy.sock mode 660 level admin

defaults
    log     global
    option   httplog
    timeout connect 10s
    timeout client  30s
    timeout server  30s

frontend stats
    bind *:8404
    stats enable
    stats uri /
    stats refresh 10s

frontend web_apps
    bind *:80
    default_backend app_servers

backend app_servers
    server dvwa lab-dvwa:80 check
    server dvna lab-dvna:9091 check
    server juice lab-juice-shop:3000 check
EOF

# Create Prometheus config
cat > config/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'tazosploit'
    static_configs:
      - targets: ['control-plane-api:8000', 'job-scheduler:8001']

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF

echo -e "${GREEN}✓ Configuration files created${NC}"
echo ""

# =============================================================================
# STEP 4: Check Docker Compose File
# =============================================================================

echo -e "${YELLOW}[4/8] Checking Docker Compose file...${NC}"

if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
    echo -e "${RED}✗ Docker Compose file not found: $DOCKER_COMPOSE_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker Compose file found: $DOCKER_COMPOSE_FILE${NC}"
echo ""

# =============================================================================
# STEP 5: Stop Existing Containers
# =============================================================================

echo -e "${YELLOW}[5/8] Stopping existing containers (if any)...${NC}"

if docker-compose -f "$DOCKER_COMPOSE_FILE" ps -q 2>/dev/null | grep -q .; then
    docker-compose -f "$DOCKER_COMPOSE_FILE" down
    echo -e "${GREEN}✓ Stopped existing containers${NC}"
else
    echo -e "${GREEN}✓ No existing containers to stop${NC}"
fi

echo ""

# =============================================================================
# STEP 6: Pull Docker Images
# =============================================================================

echo -e "${YELLOW}[6/8] Pulling Docker images...${NC}"
echo -e "${BLUE}This may take a few minutes...${NC}"

docker-compose -f "$DOCKER_COMPOSE_FILE" pull --quiet

echo -e "${GREEN}✓ Docker images pulled${NC}"
echo ""

# =============================================================================
# STEP 7: Build Custom Images
# =============================================================================

echo -e "${YELLOW}[7/8] Building custom images...${NC}"
echo -e "${BLUE}This may take a few minutes...${NC}"

docker-compose -f "$DOCKER_COMPOSE_FILE" build --quiet

echo -e "${GREEN}✓ Custom images built${NC}"
echo ""

# =============================================================================
# STEP 8: Start All Services
# =============================================================================

echo -e "${YELLOW}[8/8] Starting all services...${NC}"
echo -e "${BLUE}This may take 2-3 minutes...${NC}"

docker-compose -f "$DOCKER_COMPOSE_FILE" up -d

echo ""
echo -e "${GREEN}✓ Services started${NC}"
echo ""

# =============================================================================
# WAIT FOR SERVICES TO BE HEALTHY
# =============================================================================

echo -e "${YELLOW}Waiting for services to be healthy...${NC}"

# Wait for PostgreSQL
echo -n "  PostgreSQL..."
until docker exec tazosploit-postgres pg_isready -U tazosploit &> /dev/null; do
    sleep 2
done
echo -e " ${GREEN}✓${NC}"

# Wait for Redis
echo -n "  Redis..."
until docker exec tazosploit-redis redis-cli ping &> /dev/null; do
    sleep 2
done
echo -e " ${GREEN}✓${NC}"

# Wait for Control Plane API
echo -n "  Control Plane API..."
until curl -s http://localhost:8000/health &> /dev/null; do
    sleep 5
done
echo -e " ${GREEN}✓${NC}"

echo ""
echo -e "${GREEN}✓ All services are healthy!${NC}"
echo ""

# =============================================================================
# SUMMARY
# =============================================================================

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ TazoSploit One-Click Setup Complete!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}📊 Services Running:${NC}"
echo -e "  • TazoSploit API:           http://localhost:8000"
echo -e "  • Grafana Dashboard:       http://localhost:3001 (admin/admin)"
echo -e "  • Prometheus Metrics:       http://localhost:9090"
echo ""

echo -e "${YELLOW}🐳 Vulnerable Lab Targets:${NC}"
echo -e "  • DVWA:                    http://localhost:8081"
echo -e "  • DVNA:                    http://localhost:9091"
echo -e "  • Juice Shop:              http://localhost:3000"
echo -e "  • WebGoat:                 http://localhost:8082"
echo -e "  • HAProxy Stats:           http://localhost:8404"
echo -e "  • MySQL:                   localhost:3306 (root/root123)"
echo -e "  • PostgreSQL:              localhost:5433 (postgres/postgres)"
echo ""

echo -e "${YELLOW}📚 Documentation:${NC}"
echo -e "  • Quick Start Guide:        docs/DOCKER_SETUP.md"
echo -e "  • Architecture:            docs/ARCHITECTURE.md"
echo -e "  • Skills System:           docs/SKILLS_SYSTEM.md"
echo -e "  • Memory System:           docs/MEMORY_SYSTEM.md"
echo ""

echo -e "${YELLOW}🧪 Quick Test:${NC}"
echo -e "  curl http://localhost:8000/health"
echo ""

echo -e "${YELLOW}📋 View Logs:${NC}"
echo -e "  docker-compose -f $DOCKER_COMPOSE_FILE logs -f"
echo ""

echo -e "${YELLOW}🛑 Stop All Services:${NC}"
echo -e "  docker-compose -f $DOCKER_COMPOSE_FILE down"
echo ""

echo -e "${YELLOW}🗑️ Remove Everything:${NC}"
echo -e "  docker-compose -f $DOCKER_COMPOSE_FILE down -v --rmi all"
echo ""

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🎯 Ready for full kill chain testing!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
