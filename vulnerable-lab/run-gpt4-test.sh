#!/bin/bash
# NeuroSploit with GPT-4 - Production-Grade AI Pentesting

set -e

echo "=========================================="
echo "NeuroSploit with GPT-4"
echo "Production AI Pentesting"
echo "=========================================="

# Check for API key
if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ ERROR: OPENAI_API_KEY not set"
    echo ""
    echo "Get your API key from: https://platform.openai.com/api-keys"
    echo "Then run:"
    echo "  export OPENAI_API_KEY='your-key-here'"
    echo ""
    exit 1
fi

# OpenAI API configuration
LLM_API_BASE="${LLM_API_BASE:-https://api.openai.com/v1}"
LLM_MODEL="${LLM_MODEL:-gpt-4-turbo}"

mkdir -p logs
rm -f logs/*.jsonl logs/*.log logs/*.json logs/*.md 2>/dev/null

TARGET="10.0.2.20"

echo "Target: $TARGET (DVWA)"
echo "Model: $LLM_MODEL"
echo "Mode: FULLY AUTONOMOUS"
echo ""

# Build image if needed
docker build -t neurosploit-kali:minimal -f ../kali-executor/Dockerfile.minimal ../kali-executor 2>&1 | tail -3

echo ""
echo "Starting GPT-4-powered penetration test..."
echo "=========================================="

# Run with GPT-4 API
docker run --rm -it \
  --network vulnerable-lab_dmz \
  -e LLM_API_BASE="$LLM_API_BASE" \
  -e LLM_MODEL="$LLM_MODEL" \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v "$(pwd)/logs:/pentest/logs" \
  -v "$(pwd)/../kali-executor/open-interpreter:/opt/neurosploit" \
  neurosploit-kali:minimal \
  python3 /opt/neurosploit/dynamic_agent.py \
  --target "$TARGET" \
  --objective "Perform a comprehensive security assessment on the target. Find vulnerabilities, exploit them, and extract any sensitive data you can access. Document all findings." \
  --max-iterations 30 2>&1 | tee logs/gpt4_run.log

echo ""
echo "=========================================="
echo "GPT-4 Test Complete"
echo "=========================================="
echo "Logs: ./logs/"
echo "Check logs/COMPREHENSIVE_REPORT_*.md for findings"
