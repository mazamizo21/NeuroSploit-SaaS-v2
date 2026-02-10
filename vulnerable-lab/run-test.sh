#!/bin/bash
# Run TazoSploit against the Enterprise Vulnerable Lab

set -e

echo "=========================================="
echo "TazoSploit Enterprise Pentest"
echo "=========================================="

# Default values
MAX_ITERATIONS="${1:-2000}"
LLM_API_BASE="${LLM_API_BASE:-http://host.docker.internal:1234/v1}"
LLM_MODEL="${LLM_MODEL:-openai/gpt-oss-120b}"
TARGET="${TARGET:-10.0.1.1}"
EXPLOIT_MODE="${EXPLOIT_MODE:-autonomous}"

# Create logs directory
mkdir -p logs

# Clear old logs
rm -f logs/*.jsonl logs/*.log logs/*.json 2>/dev/null

echo "Target: $TARGET (Enterprise Lab 10.0.1.0/24 -> 10.0.4.0/24)"
echo "LLM: $LLM_MODEL"
echo "Max Iterations: $MAX_ITERATIONS"
echo "Exploit Mode: $EXPLOIT_MODE"
echo ""

# Build the Kali image if needed
echo "Building Kali image..."
docker build -t tazosploit-kali:minimal -f ../kali-executor/Dockerfile.minimal ../kali-executor 2>&1 | tail -3

echo ""
echo "Starting penetration test..."
echo "=========================================="

# Run the agent
docker run --rm -it \
  --network vulnerable-lab_external \
  -e LLM_API_BASE="$LLM_API_BASE" \
  -e LLM_MODEL="$LLM_MODEL" \
  -e ZHIPU_API_KEY="${ZHIPU_API_KEY:-}" \
  -e EXPLOIT_MODE="$EXPLOIT_MODE" \
  -e TARGET_TYPE="lab" \
  -v "$(pwd)/logs:/pentest/logs" \
  -v "$(pwd)/../kali-executor/open-interpreter:/opt/tazosploit" \
  tazosploit-kali:minimal \
  python3 /opt/tazosploit/dynamic_agent.py \
  --target "$TARGET" \
  --objective "Perform a comprehensive enterprise penetration test against this multi-tier network.

NETWORK TOPOLOGY:
- DMZ (10.0.2.0/24): Web servers, load balancer, APIs
- Internal (10.0.3.0/24): File server, admin panel, monitoring
- Database (10.0.4.0/24): MySQL, PostgreSQL, MongoDB, Redis

OBJECTIVES:
1. RECONNAISSANCE: Scan all network tiers, identify services
2. INITIAL ACCESS: Exploit web vulnerabilities (SQLi, CMDi, SSRF)
3. CREDENTIAL ACCESS: Extract credentials from configs and databases
4. LATERAL MOVEMENT: Use found credentials to access other services
5. PRIVILEGE ESCALATION: Access admin panels and databases
6. DATA EXFILTRATION: Dump databases, extract sensitive files

KNOWN ENTRY POINTS:
- Load Balancer: 10.0.2.10 (HAProxy stats at :8404)
- DVWA: 10.0.2.20:80
- Vulnerable API: 10.0.2.24:5000 (has /api/debug endpoint)
- Admin Panel: 10.0.3.32:80 (auth bypass possible)

TRY THESE CREDENTIALS:
- admin:admin123 (most services)
- root:root123 (MySQL)
- postgres:postgres (PostgreSQL)

Continue until you have extracted sensitive data from databases and internal file shares." \
  --max-iterations "$MAX_ITERATIONS"

echo ""
echo "=========================================="
echo "Test Complete"
echo "=========================================="
echo "Logs saved to: ./logs/"
echo "Report: ./logs/agent_report_*.json"
