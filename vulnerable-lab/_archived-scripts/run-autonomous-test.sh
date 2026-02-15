#!/bin/bash
# TRULY AUTONOMOUS AI Pentest - NO CHEATING
# The AI gets ONLY a target and must figure everything out itself

set -e

echo "=========================================="
echo "TazoSploit AUTONOMOUS Mode"
echo "NO HINTS - AI must discover everything"
echo "=========================================="

LLM_API_BASE="${LLM_API_BASE:-http://host.docker.internal:1234/v1}"
LLM_MODEL="${LLM_MODEL:-openai/gpt-oss-120b}"
MAX_ITERATIONS="${MAX_ITERATIONS:-2000}"
EXPLOIT_MODE="${EXPLOIT_MODE:-autonomous}"

mkdir -p logs
rm -f logs/*.jsonl logs/*.log logs/*.json logs/*.md 2>/dev/null

# Pick ONE target - DVWA (a single vulnerable web app)
TARGET="${TARGET:-10.0.2.20}"

echo "Target: $TARGET (single web application)"
echo "LLM: $LLM_MODEL"
echo "Mode: FULLY AUTONOMOUS - No hints provided"
echo "Max Iterations: $MAX_ITERATIONS"
echo "Exploit Mode: $EXPLOIT_MODE"
echo ""

# Build image if needed
docker build -t tazosploit-kali:minimal -f ../kali-executor/Dockerfile.minimal ../kali-executor 2>&1 | tail -3

echo ""
echo "Starting AUTONOMOUS penetration test..."
echo "AI must discover and exploit vulnerabilities WITHOUT guidance"
echo "=========================================="

# TRULY DYNAMIC - Just target + simple objective
docker run --rm -it \
  --network vulnerable-lab_dmz \
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
  --objective "Perform a comprehensive security assessment on the target. Find vulnerabilities, exploit them, and extract any sensitive data you can access. Document all findings." \
  --max-iterations "$MAX_ITERATIONS" 2>&1 | tee logs/autonomous_run.log

echo ""
echo "=========================================="
echo "Autonomous Test Complete"
echo "=========================================="
echo "Logs: ./logs/"
echo "Check logs/COMPREHENSIVE_REPORT_*.md for findings"
