#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "  ${CYAN}ℹ${NC}  $*"; }
success() { echo -e "  ${GREEN}✅${NC} $*"; }
warn()    { echo -e "  ${YELLOW}⚠️${NC}  $*"; }
fail()    { echo -e "  ${RED}❌${NC} $*"; exit 1; }

# Detect compose command
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    fail "Docker Compose not found"
fi

# Parse flags
WITH_LAB=false
REBUILD=false
for arg in "$@"; do
    case "$arg" in
        --with-lab) WITH_LAB=true ;;
        --rebuild)  REBUILD=true ;;
        --help|-h)
            echo "Usage: $0 [--with-lab] [--rebuild]"
            exit 0 ;;
    esac
done

echo -e "${BOLD}${CYAN}▶ Starting TazoSploit...${NC}"

# Check Docker daemon
docker info &>/dev/null || fail "Docker daemon not running"

# Rebuild if requested
if [ "$REBUILD" = true ]; then
    info "Rebuilding images..."
    $COMPOSE_CMD build --no-cache 2>&1 | tail -3
fi

# Start in order
info "Starting infrastructure..."
$COMPOSE_CMD up -d postgres redis
sleep 3

info "Starting control plane..."
$COMPOSE_CMD up -d control-plane-api
sleep 2

info "Starting execution plane..."
$COMPOSE_CMD up -d job-scheduler worker

info "Starting Kali executor pool..."
$COMPOSE_CMD up -d kali-executor

if [ "$WITH_LAB" = true ]; then
    info "Starting DVWA lab..."
    $COMPOSE_CMD --profile dev up -d dvwa
fi

# Start observability (don't fail)
$COMPOSE_CMD up -d grafana prometheus 2>/dev/null || true

# Quick health check
sleep 3
RUNNING=$(docker ps --filter "name=tazosploit" --format '{{.Names}}' | wc -l | tr -d ' ')
echo ""
success "TazoSploit running ($RUNNING containers)"
echo -e "  API: ${CYAN}http://localhost:8000${NC}  |  Grafana: ${CYAN}http://localhost:3001${NC}"
if [ "$WITH_LAB" = true ]; then
    echo -e "  DVWA: ${CYAN}http://localhost:8888${NC}"
fi

# LLM check
if ! curl -s --connect-timeout 1 http://localhost:1234/v1/models &>/dev/null; then
    if ! grep -q "ANTHROPIC_API_KEY=sk-" .env 2>/dev/null; then
        warn "No LLM detected — start LM Studio or set ANTHROPIC_API_KEY in .env"
    fi
fi
