#!/bin/bash
# NeuroSploit with Claude API - Production-Grade AI Pentesting
# Claude Sonnet 3.5 has excellent reasoning and security knowledge

set -e

echo "=========================================="
echo "NeuroSploit with Claude Sonnet 3.5"
echo "Production AI Pentesting"
echo "=========================================="

# Check for API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "❌ ERROR: ANTHROPIC_API_KEY not set"
    echo ""
    echo "Get your API key from: https://console.anthropic.com/"
    echo "Then run:"
    echo "  export ANTHROPIC_API_KEY='your-key-here'"
    echo ""
    exit 1
fi

# Claude API configuration
# Using OpenAI-compatible endpoint via LiteLLM or direct Anthropic SDK
LLM_API_BASE="${LLM_API_BASE:-https://api.anthropic.com}"
LLM_MODEL="${LLM_MODEL:-claude-sonnet-3-5-20241022}"

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
echo "Starting Claude-powered penetration test..."
echo "=========================================="

# Run with Claude API
docker run --rm -it \
  --network vulnerable-lab_dmz \
  -e LLM_API_BASE="$LLM_API_BASE" \
  -e LLM_MODEL="$LLM_MODEL" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -v "$(pwd)/logs:/pentest/logs" \
  -v "$(pwd)/../kali-executor/open-interpreter:/opt/neurosploit" \
  neurosploit-kali:minimal \
  python3 /opt/neurosploit/dynamic_agent.py \
  --target "$TARGET" \
  --objective "Perform a comprehensive security assessment on the target. Find vulnerabilities, exploit them, and extract any sensitive data you can access. Document all findings." \
  --max-iterations 30 2>&1 | tee logs/claude_run.log

echo ""
echo "=========================================="
echo "Claude Test Complete"
echo "=========================================="
echo "Logs: ./logs/"
echo "Check logs/COMPREHENSIVE_REPORT_*.md for findings"
