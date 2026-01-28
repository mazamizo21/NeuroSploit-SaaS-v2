#!/bin/bash
# TazoSploit  v2 - Infrastructure Test Script
# Tests PostgreSQL and Redis connectivity

set -e

echo "=============================================="
echo "TazoSploit  v2 - Infrastructure Tests"
echo "=============================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

# Test 1: PostgreSQL
echo ""
echo "Testing PostgreSQL..."
if docker exec tazosploit-postgres pg_isready -U tazosploit > /dev/null 2>&1; then
    pass "PostgreSQL is ready"
else
    fail "PostgreSQL is not ready"
fi

# Test 2: PostgreSQL connection
if docker exec tazosploit-postgres psql -U tazosploit -c "SELECT 1" > /dev/null 2>&1; then
    pass "PostgreSQL connection works"
else
    fail "PostgreSQL connection failed"
fi

# Test 3: Redis
echo ""
echo "Testing Redis..."
if docker exec tazosploit-redis redis-cli ping | grep -q PONG; then
    pass "Redis is ready"
else
    fail "Redis is not ready"
fi

# Test 4: Redis set/get
docker exec tazosploit-redis redis-cli SET test_key "test_value" > /dev/null
RESULT=$(docker exec tazosploit-redis redis-cli GET test_key)
if [ "$RESULT" == "test_value" ]; then
    pass "Redis set/get works"
    docker exec tazosploit-redis redis-cli DEL test_key > /dev/null
else
    fail "Redis set/get failed"
fi

echo ""
echo "=============================================="
echo "All infrastructure tests passed!"
echo "=============================================="
