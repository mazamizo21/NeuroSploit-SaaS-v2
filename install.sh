#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# TazoSploit SaaS v2 — One-Click Installer
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Colors & Helpers -------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}ℹ ${NC} $*"; }
success() { echo -e "${GREEN}✅${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠️ ${NC} $*"; }
fail()    { echo -e "${RED}❌${NC} $*"; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}▶ $*${NC}"; }
spinner() {
    local pid=$1 msg=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${spin:i++%${#spin}:1} %s" "$msg"
        sleep 0.1
    done
    printf "\r"
}

# --- Parse Flags ------------------------------------------------------------
WITH_LAB=false
REBUILD=false
for arg in "$@"; do
    case "$arg" in
        --with-lab) WITH_LAB=true ;;
        --rebuild)  REBUILD=true ;;
        --help|-h)
            echo "Usage: $0 [--with-lab] [--rebuild]"
            echo "  --with-lab   Also start the DVWA vulnerable lab"
            echo "  --rebuild    Force rebuild all Docker images"
            exit 0 ;;
    esac
done

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║         TazoSploit SaaS v2 Installer        ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================================
# Step 1: Check Prerequisites
# ============================================================================
step "Checking prerequisites..."

# Docker
if ! command -v docker &>/dev/null; then
    fail "Docker not found. Install from https://docs.docker.com/get-docker/"
fi
DOCKER_VERSION=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
success "Docker $DOCKER_VERSION"

# Docker Compose (v2 plugin or standalone)
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
    COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "v2+")
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
    COMPOSE_VERSION=$(docker-compose --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
else
    fail "Docker Compose not found. Install from https://docs.docker.com/compose/install/"
fi
success "Docker Compose ($COMPOSE_VERSION)"

# Python
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        success "Python $PY_VERSION"
    else
        warn "Python $PY_VERSION found (3.11+ recommended). Continuing anyway."
    fi
else
    warn "Python3 not found on host (only needed for local development)"
fi

# Git
if command -v git &>/dev/null; then
    success "Git $(git --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
else
    warn "Git not found (optional)"
fi

# Docker daemon running?
if ! docker info &>/dev/null; then
    fail "Docker daemon not running. Start Docker Desktop or run: sudo systemctl start docker"
fi
success "Docker daemon running"

# ============================================================================
# Step 2: Configure Environment
# ============================================================================
step "Configuring environment..."

if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        # Generate secure secret key
        SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || echo "dev-$(date +%s)-$(od -An -N16 -tx1 /dev/urandom | tr -d ' ')")
        sed -i.bak "s|change-this-to-a-secure-random-string-in-production|${SECRET_KEY}|" .env
        rm -f .env.bak
        success "Created .env from .env.example with secure secret key"
    else
        warn "No .env.example found — using Docker Compose defaults"
    fi
else
    success ".env already exists"
fi

# Auto-detect LLM provider
step "Detecting LLM provider..."
LM_STUDIO_RUNNING=false
if curl -s --connect-timeout 2 http://localhost:1234/v1/models &>/dev/null; then
    LM_STUDIO_RUNNING=true
    success "LM Studio detected at localhost:1234"
elif curl -s --connect-timeout 2 http://127.0.0.1:1234/v1/models &>/dev/null; then
    LM_STUDIO_RUNNING=true
    success "LM Studio detected at 127.0.0.1:1234"
fi

if [ "$LM_STUDIO_RUNNING" = false ]; then
    if grep -q "ANTHROPIC_API_KEY=." .env 2>/dev/null; then
        success "Claude API key found in .env"
    else
        warn "LM Studio not running and no Claude API key set."
        echo -e "  ${YELLOW}To use Claude API, add to .env:${NC}"
        echo "    LLM_PROVIDER=claude"
        echo "    ANTHROPIC_API_KEY=sk-ant-..."
        echo -e "  ${YELLOW}To use LM Studio, start it and load a model at localhost:1234${NC}"
    fi
fi

# ============================================================================
# Step 3: Build Docker Images
# ============================================================================
step "Building Docker images (this may take a while)..."

BUILD_ARGS=""
if [ "$REBUILD" = true ]; then
    BUILD_ARGS="--no-cache"
    info "Forcing full rebuild (--no-cache)"
fi

# Build in dependency order
echo -e "  Building infrastructure images..."
$COMPOSE_CMD build $BUILD_ARGS postgres redis 2>&1 | tail -1 || true
success "Infrastructure images ready"

echo -e "  Building control plane..."
$COMPOSE_CMD build $BUILD_ARGS control-plane-api 2>&1 | tail -5
success "Control plane API built"

echo -e "  Building execution plane..."
$COMPOSE_CMD build $BUILD_ARGS job-scheduler worker 2>&1 | tail -5
success "Job scheduler + workers built"

echo -e "  Building Kali executor (this is the big one ~15GB)..."
$COMPOSE_CMD build $BUILD_ARGS kali-executor 2>&1 | tail -5
success "Kali executor built"

if [ "$WITH_LAB" = true ]; then
    echo -e "  Pulling DVWA vulnerable lab image..."
    docker pull vulnerables/web-dvwa 2>&1 | tail -1
    success "DVWA image ready"
fi

# ============================================================================
# Step 4: Start Infrastructure
# ============================================================================
step "Starting infrastructure (PostgreSQL, Redis)..."
$COMPOSE_CMD up -d postgres redis

# Wait for health checks
echo -n "  Waiting for PostgreSQL..."
for i in $(seq 1 30); do
    if docker exec tazosploit-postgres pg_isready -U tazosploit &>/dev/null; then
        echo ""
        success "PostgreSQL healthy"
        break
    fi
    echo -n "."
    sleep 1
    if [ "$i" -eq 30 ]; then
        echo ""
        fail "PostgreSQL failed to start within 30s"
    fi
done

echo -n "  Waiting for Redis..."
for i in $(seq 1 15); do
    if docker exec tazosploit-redis redis-cli ping 2>/dev/null | grep -q PONG; then
        echo ""
        success "Redis healthy"
        break
    fi
    echo -n "."
    sleep 1
    if [ "$i" -eq 15 ]; then
        echo ""
        fail "Redis failed to start within 15s"
    fi
done

# ============================================================================
# Step 5: Start Control Plane
# ============================================================================
step "Starting control plane API..."
$COMPOSE_CMD up -d control-plane-api

echo -n "  Waiting for API..."
for i in $(seq 1 30); do
    if curl -s --connect-timeout 1 http://localhost:8000/docs &>/dev/null; then
        echo ""
        success "Control plane API ready at http://localhost:8000"
        break
    fi
    echo -n "."
    sleep 1
    if [ "$i" -eq 30 ]; then
        echo ""
        warn "Control plane API not responding yet (may still be starting)"
    fi
done

# ============================================================================
# Step 6: Start Execution Plane
# ============================================================================
step "Starting execution plane (scheduler + workers)..."
$COMPOSE_CMD up -d job-scheduler worker
success "Job scheduler + 2 workers started"

# ============================================================================
# Step 7: Start Kali Executor Pool
# ============================================================================
step "Starting Kali executor pool (3 containers)..."
$COMPOSE_CMD up -d kali-executor
success "Kali executor pool started"

# ============================================================================
# Step 8: Optional Vulnerable Lab
# ============================================================================
if [ "$WITH_LAB" = true ]; then
    step "Starting vulnerable lab (DVWA)..."
    $COMPOSE_CMD --profile dev up -d dvwa
    
    echo -n "  Waiting for DVWA..."
    for i in $(seq 1 30); do
        if curl -s --connect-timeout 1 http://localhost:8888/login.php 2>/dev/null | grep -q "DVWA"; then
            echo ""
            success "DVWA ready at http://localhost:8888"
            break
        fi
        echo -n "."
        sleep 1
        if [ "$i" -eq 30 ]; then
            echo ""
            warn "DVWA not responding yet (may need database setup)"
        fi
    done
fi

# ============================================================================
# Step 9: Start Observability (optional, don't fail)
# ============================================================================
step "Starting observability stack..."
$COMPOSE_CMD up -d grafana prometheus 2>/dev/null && success "Grafana + Prometheus started" || warn "Observability services skipped (missing config files)"

# ============================================================================
# Step 10: Health Check Summary
# ============================================================================
step "Running final health checks..."

echo ""
declare -A SERVICES=(
    ["PostgreSQL"]="docker exec tazosploit-postgres pg_isready -U tazosploit"
    ["Redis"]="docker exec tazosploit-redis redis-cli ping"
    ["Control Plane API"]="curl -sf --connect-timeout 2 http://localhost:8000/docs"
)

ALL_HEALTHY=true
for svc in "${!SERVICES[@]}"; do
    if eval "${SERVICES[$svc]}" &>/dev/null; then
        success "$svc: healthy"
    else
        warn "$svc: not responding"
        ALL_HEALTHY=false
    fi
done

# Check containers running
RUNNING=$(docker ps --filter "name=tazosploit" --format '{{.Names}}' | wc -l | tr -d ' ')
info "$RUNNING TazoSploit containers running"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║       TazoSploit Installation Complete!      ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Endpoints:${NC}"
echo -e "  Control Plane API:  ${CYAN}http://localhost:8000${NC}"
echo -e "  API Docs (Swagger): ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  Grafana Dashboard:  ${CYAN}http://localhost:3001${NC} (admin/admin)"
echo -e "  Prometheus:         ${CYAN}http://localhost:9090${NC}"
if [ "$WITH_LAB" = true ]; then
    echo -e "  DVWA Lab:           ${CYAN}http://localhost:8888${NC} (admin/password)"
fi
echo ""
echo -e "${BOLD}Database:${NC}"
echo -e "  PostgreSQL:  localhost:5432 (tazosploit/tazosploit_dev)"
echo -e "  Redis:       localhost:6379"
echo ""
echo -e "${BOLD}Quick Commands:${NC}"
echo -e "  Start:   ${CYAN}./start.sh${NC}"
echo -e "  Stop:    ${CYAN}./stop.sh${NC}"
echo -e "  Logs:    ${CYAN}docker compose logs -f${NC}"
echo -e "  Status:  ${CYAN}docker compose ps${NC}"
echo ""
if [ "$LM_STUDIO_RUNNING" = false ]; then
    echo -e "${YELLOW}⚠️  Remember to start LM Studio or configure Claude API in .env${NC}"
fi
