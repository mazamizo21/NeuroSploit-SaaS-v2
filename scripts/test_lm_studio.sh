#!/bin/bash
# TazoSploit  v2 - LM Studio Connection Test
# Tests connectivity between Kali container and LM Studio

echo "=============================================="
echo "TazoSploit  v2 - LM Studio Connection Test"
echo "=============================================="

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# Test LM Studio from host
info "Testing LM Studio on host (localhost:1234)..."
MODELS=$(curl -s http://localhost:1234/v1/models 2>/dev/null)
if echo "$MODELS" | grep -q "data"; then
    pass "LM Studio is running on host"
    echo "  Models: $(echo "$MODELS" | python3 -c "import sys,json; d=json.load(sys.stdin); print([m['id'] for m in d.get('data',[])])" 2>/dev/null || echo "parsing failed")"
else
    fail "LM Studio not reachable on localhost:1234"
    echo "  Please ensure LM Studio is running with a model loaded"
    exit 1
fi

# Test from Docker using host.docker.internal
info "Testing LM Studio from Docker (host.docker.internal:1234)..."
DOCKER_TEST=$(docker run --rm --add-host=host.docker.internal:host-gateway curlimages/curl:latest \
    curl -s http://host.docker.internal:1234/v1/models 2>/dev/null)

if echo "$DOCKER_TEST" | grep -q "data"; then
    pass "LM Studio reachable from Docker containers"
else
    fail "Cannot reach LM Studio from Docker"
    echo "  Trying alternative method..."
    
    # Get host IP
    HOST_IP=$(ifconfig en0 | grep "inet " | awk '{print $2}')
    info "Trying with host IP: $HOST_IP"
    
    DOCKER_TEST2=$(docker run --rm curlimages/curl:latest \
        curl -s "http://${HOST_IP}:1234/v1/models" 2>/dev/null)
    
    if echo "$DOCKER_TEST2" | grep -q "data"; then
        pass "LM Studio reachable via host IP: $HOST_IP"
        echo "  Use LLM_API_BASE=http://${HOST_IP}:1234/v1"
    else
        fail "Cannot reach LM Studio from Docker via any method"
        exit 1
    fi
fi

echo ""
echo "=============================================="
pass "LM Studio connection verified!"
echo "=============================================="
