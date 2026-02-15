#!/bin/bash
# TazoSploit with GPT-4 - Production-Grade AI Pentesting

set -e

echo "=========================================="
echo "TazoSploit with GPT-4"
echo "Production AI Pentesting"
echo "=========================================="

# Check for API key
# LM Studio local API configuration (no API key needed)
LLM_API_BASE="${LLM_API_BASE:-http://host.docker.internal:1234/v1}"
LLM_MODEL="${LLM_MODEL:-huihui-gpt-oss-120b-abliterated}"

mkdir -p logs
rm -f logs/*.jsonl logs/*.log logs/*.json logs/*.md 2>/dev/null

TARGET="10.0.2.20"

echo "Target: $TARGET (DVWA)"
echo "Model: $LLM_MODEL"
echo "Mode: FULLY AUTONOMOUS"
echo ""

# Build image if needed
docker build -t tazosploit-kali:minimal -f ../kali-executor/Dockerfile.minimal ../kali-executor 2>&1 | tail -3

echo ""
echo "Starting GPT-4-powered penetration test..."
echo "=========================================="

# Run with GPT-4 API
docker run --rm -it \
  --network vulnerable-lab_dmz \
  -e LLM_API_BASE="$LLM_API_BASE" \
  -e LLM_MODEL="$LLM_MODEL" \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e TARGET="$TARGET" \
  -v "$(pwd)/logs:/pentest/logs" \
  -v "$(pwd)/../kali-executor/open-interpreter:/opt/tazosploit" \
  tazosploit-kali:minimal \
  python3 /opt/tazosploit/dynamic_agent.py \
  --target "$TARGET" \
  --objective "Perform a comprehensive security assessment on the target. Find vulnerabilities, exploit them, and extract any sensitive data you can access. Document all findings." 2>&1 | tee logs/gpt4_run.log

echo ""
echo "=========================================="
echo "GPT-4 Test Complete"
echo "=========================================="
echo "Logs: ./logs/"
echo "Check logs/COMPREHENSIVE_REPORT_*.md for findings"
