#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Detect compose command
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo -e "${RED}❌${NC} Docker Compose not found"; exit 1
fi

echo -e "${BOLD}${CYAN}▶ Stopping TazoSploit...${NC}"

# Stop all services (including dev profile)
$COMPOSE_CMD --profile dev down "$@"

echo -e "  ${GREEN}✅${NC} All TazoSploit services stopped"
echo ""
echo -e "  Data preserved in Docker volumes. To remove everything:"
echo -e "    ${CYAN}docker compose --profile dev down -v${NC}"
