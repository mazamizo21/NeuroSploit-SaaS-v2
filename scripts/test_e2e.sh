#!/bin/bash
# TazoSploit  v2 - End-to-End Test Script
# Tests the complete flow from infrastructure to API

set -e

echo "=============================================="
echo "TazoSploit  v2 - End-to-End Tests"
echo "=============================================="

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# =============================================================================
# Step 1: Infrastructure
# =============================================================================

echo ""
info "Step 1: Testing Infrastructure..."

# PostgreSQL
if docker exec tazosploit-postgres pg_isready -U tazosploit > /dev/null 2>&1; then
    pass "PostgreSQL is healthy"
else
    fail "PostgreSQL is not ready"
fi

# Redis
if docker exec tazosploit-redis redis-cli ping | grep -q PONG; then
    pass "Redis is healthy"
else
    fail "Redis is not ready"
fi

# =============================================================================
# Step 2: Control Plane API
# =============================================================================

echo ""
info "Step 2: Testing Control Plane API..."

# Health check (from inside container)
HEALTH=$(docker exec tazosploit-api curl -s http://localhost:8000/health 2>/dev/null || echo "failed")
if echo "$HEALTH" | grep -q "healthy"; then
    pass "Control Plane API is healthy"
else
    fail "Control Plane API health check failed: $HEALTH"
fi

# Root endpoint
ROOT=$(docker exec tazosploit-api curl -s http://localhost:8000/ 2>/dev/null || echo "failed")
if echo "$ROOT" | grep -q "TazoSploit"; then
    pass "Control Plane root endpoint works"
else
    fail "Control Plane root endpoint failed"
fi

# =============================================================================
# Step 3: Kali Container
# =============================================================================

echo ""
info "Step 3: Testing Kali Container..."

# Check if Kali image exists
if docker images | grep -q "tazosploit-kali"; then
    pass "Kali container image exists"
else
    fail "Kali container image not found"
fi

# Test nmap in Kali
NMAP_TEST=$(docker run --rm tazosploit-kali:minimal bash -c "nmap --version" 2>&1 | grep -i "nmap" || echo "failed")
if echo "$NMAP_TEST" | grep -qi "nmap"; then
    pass "Nmap is available in Kali container"
else
    info "Nmap test output: $NMAP_TEST"
fi

# =============================================================================
# Step 4: Database Schema
# =============================================================================

echo ""
info "Step 4: Testing Database Schema..."

# Check tables exist
TABLES=$(docker exec tazosploit-postgres psql -U tazosploit -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'" 2>/dev/null | tr -d ' ')
if [ "$TABLES" -gt 5 ]; then
    pass "Database has $TABLES tables"
else
    fail "Database schema incomplete (only $TABLES tables)"
fi

# Check seed data
TENANT=$(docker exec tazosploit-postgres psql -U tazosploit -t -c "SELECT COUNT(*) FROM tenants" 2>/dev/null | tr -d ' ')
if [ "$TENANT" -gt 0 ]; then
    pass "Seed tenant data exists"
else
    fail "No seed data in tenants table"
fi

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "=============================================="
echo -e "${GREEN}All E2E tests passed!${NC}"
echo "=============================================="
echo ""
echo "Running containers:"
docker ps --format "  - {{.Names}}: {{.Status}}" | grep tazosploit
echo ""
echo "Next steps:"
echo "  1. Create GitHub repo: https://github.com/mazamizo21/TazoSploit--v2"
echo "  2. Push code: git push -u origin main"
echo "  3. Start LM Studio with gpt-oss-120b model"
echo "  4. Run full pentest test against DVWA"
