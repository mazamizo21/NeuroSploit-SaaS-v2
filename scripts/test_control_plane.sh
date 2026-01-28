#!/bin/bash
# TazoSploit  v2 - Control Plane Test Script
# Tests the Control Plane API endpoints

set -e

echo "=============================================="
echo "TazoSploit  v2 - Control Plane Tests"
echo "=============================================="

API_URL="${API_URL:-http://localhost:8000}"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

# Test 1: Health endpoint
echo ""
echo "Testing health endpoint..."
HEALTH=$(curl -s "$API_URL/health")
if echo "$HEALTH" | grep -q "healthy"; then
    pass "Health endpoint returns healthy"
    echo "  Response: $HEALTH"
else
    fail "Health endpoint failed: $HEALTH"
fi

# Test 2: Root endpoint
echo ""
echo "Testing root endpoint..."
ROOT=$(curl -s "$API_URL/")
if echo "$ROOT" | grep -q "TazoSploit"; then
    pass "Root endpoint works"
else
    fail "Root endpoint failed"
fi

# Test 3: API docs
echo ""
echo "Testing API docs..."
DOCS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/docs")
if [ "$DOCS" == "200" ]; then
    pass "API docs available at $API_URL/api/docs"
else
    fail "API docs not available (HTTP $DOCS)"
fi

echo ""
echo "=============================================="
echo "All Control Plane tests passed!"
echo "=============================================="
