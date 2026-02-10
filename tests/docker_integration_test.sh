#!/bin/bash
# TazoSploit  v2 - Docker Integration Tests
# Tests all Phase 1 features in actual Docker environment

set -e  # Exit on error

echo "================================================================================"
echo "TazoSploit  v2 - Docker Integration Tests"
echo "================================================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
test_start() {
    echo -e "${YELLOW}Testing: $1${NC}"
    TESTS_RUN=$((TESTS_RUN + 1))
}

test_pass() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo ""
}

test_fail() {
    echo -e "${RED}❌ FAIL: $1${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo ""
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

echo "Step 1: Starting core infrastructure services..."
echo "--------------------------------------------------------------------------------"
docker compose -f docker-compose.yml up -d postgres redis minio

echo "Waiting for services to be healthy..."
sleep 10

# Test PostgreSQL
test_start "PostgreSQL Connection"
if docker exec tazosploit-postgres pg_isready -U tazosploit > /dev/null 2>&1; then
    test_pass "PostgreSQL is running and accepting connections"
else
    test_fail "PostgreSQL connection failed"
fi

# Test Redis
test_start "Redis Connection"
if docker exec tazosploit-redis redis-cli ping | grep -q "PONG"; then
    test_pass "Redis is running and responding"
else
    test_fail "Redis connection failed"
fi

echo ""
echo "Step 2: Building and starting application services..."
echo "--------------------------------------------------------------------------------"

# Build control plane
test_start "Control Plane Build"
if docker compose -f docker-compose.yml build api > /dev/null 2>&1; then
    test_pass "Control plane built successfully"
else
    test_fail "Control plane build failed"
fi

# Start control plane
docker compose -f docker-compose.yml up -d api
echo "Waiting for control plane to start..."
sleep 15

# Test Control Plane Health
test_start "Control Plane Health Check"
HEALTH_RESPONSE=$(curl -s http://localhost:8000/health || echo "failed")
if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    test_pass "Control plane is healthy"
    echo "Response: $HEALTH_RESPONSE"
else
    test_fail "Control plane health check failed"
    echo "Response: $HEALTH_RESPONSE"
fi

echo ""
echo "Step 3: Testing MITRE ATT&CK API Endpoints..."
echo "--------------------------------------------------------------------------------"

# Test MITRE - List Techniques
test_start "MITRE - List Techniques"
RESPONSE=$(curl -s http://localhost:8000/api/v1/mitre/techniques?limit=5)
if echo "$RESPONSE" | grep -q "T10"; then
    test_pass "MITRE techniques endpoint working"
    echo "Sample: $(echo $RESPONSE | jq -r '.[0].id' 2>/dev/null || echo 'JSON parse failed')"
else
    test_fail "MITRE techniques endpoint failed"
fi

# Test MITRE - Get Specific Technique
test_start "MITRE - Get Technique T1046"
RESPONSE=$(curl -s http://localhost:8000/api/v1/mitre/techniques/T1046)
if echo "$RESPONSE" | grep -q "Network Service Discovery"; then
    test_pass "MITRE technique lookup working"
else
    test_fail "MITRE technique lookup failed"
fi

# Test MITRE - List Tactics
test_start "MITRE - List Tactics"
RESPONSE=$(curl -s http://localhost:8000/api/v1/mitre/tactics)
if echo "$RESPONSE" | grep -q "reconnaissance"; then
    test_pass "MITRE tactics endpoint working"
else
    test_fail "MITRE tactics endpoint failed"
fi

# Test MITRE - Tool Mapping
test_start "MITRE - Tool Mapping (nmap)"
RESPONSE=$(curl -s http://localhost:8000/api/v1/mitre/tools/nmap/techniques)
if echo "$RESPONSE" | grep -q "T1046"; then
    test_pass "MITRE tool mapping working"
else
    test_fail "MITRE tool mapping failed"
fi

# Test MITRE - Coverage Stats
test_start "MITRE - Coverage Statistics"
RESPONSE=$(curl -s http://localhost:8000/api/v1/mitre/coverage)
if echo "$RESPONSE" | grep -q "total_techniques"; then
    test_pass "MITRE coverage stats working"
    echo "Stats: $(echo $RESPONSE | jq -r '.total_techniques' 2>/dev/null || echo 'N/A') techniques"
else
    test_fail "MITRE coverage stats failed"
fi

echo ""
echo "Step 4: Testing Scheduled Jobs API Endpoints..."
echo "--------------------------------------------------------------------------------"

# Test Scheduled Jobs - Get Patterns
test_start "Scheduled Jobs - Get Cron Patterns"
RESPONSE=$(curl -s http://localhost:8000/api/v1/scheduled-jobs/patterns)
if echo "$RESPONSE" | grep -q "every_15_minutes"; then
    test_pass "Cron patterns endpoint working"
else
    test_fail "Cron patterns endpoint failed"
fi

echo ""
echo "Step 5: Testing Database Connectivity..."
echo "--------------------------------------------------------------------------------"

# Test database tables exist
test_start "Database Schema - Check Tables"
TABLES=$(docker exec tazosploit-postgres psql -U tazosploit -d tazosploit -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null | tr -d ' ')
if [ "$TABLES" -gt 0 ]; then
    test_pass "Database schema created ($TABLES tables)"
else
    test_fail "Database schema not found"
fi

echo ""
echo "Step 6: Testing Service Dependencies..."
echo "--------------------------------------------------------------------------------"

# Test Control Plane can connect to PostgreSQL
test_start "Control Plane → PostgreSQL Connection"
DB_STATUS=$(curl -s http://localhost:8000/health/detailed | jq -r '.dependencies.database' 2>/dev/null || echo "failed")
if echo "$DB_STATUS" | grep -q "healthy"; then
    test_pass "Control plane connected to PostgreSQL"
else
    test_fail "Control plane cannot connect to PostgreSQL"
fi

# Test Control Plane can connect to Redis
test_start "Control Plane → Redis Connection"
REDIS_STATUS=$(curl -s http://localhost:8000/health/detailed | jq -r '.dependencies.redis' 2>/dev/null || echo "failed")
if echo "$REDIS_STATUS" | grep -q "healthy"; then
    test_pass "Control plane connected to Redis"
else
    test_fail "Control plane cannot connect to Redis"
fi

echo ""
echo "Step 7: Testing API Documentation..."
echo "--------------------------------------------------------------------------------"

# Test OpenAPI docs
test_start "OpenAPI Documentation"
DOCS_RESPONSE=$(curl -s http://localhost:8000/api/docs)
if echo "$DOCS_RESPONSE" | grep -q "swagger"; then
    test_pass "API documentation accessible at /api/docs"
else
    test_fail "API documentation not accessible"
fi

echo ""
echo "================================================================================"
echo "Test Summary"
echo "================================================================================"
echo ""
echo "Total Tests Run:    $TESTS_RUN"
echo -e "${GREEN}Tests Passed:       $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Tests Failed:       $TESTS_FAILED${NC}"
else
    echo "Tests Failed:       $TESTS_FAILED"
fi
echo ""

PASS_RATE=$((TESTS_PASSED * 100 / TESTS_RUN))
echo "Pass Rate:          $PASS_RATE%"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed! Phase 1 is working in Docker.${NC}"
    echo ""
    echo "Services running:"
    echo "  - Control Plane API: http://localhost:8000"
    echo "  - API Documentation: http://localhost:8000/api/docs"
    echo ""
    echo "To stop services: docker compose -f docker-compose.yml down"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Check logs above.${NC}"
    echo ""
    echo "View logs:"
    echo "  docker compose -f docker-compose.yml logs api"
    echo "  docker compose -f docker-compose.yml logs postgres"
    echo "  docker compose -f docker-compose.yml logs redis"
    echo ""
    exit 1
fi
