#!/bin/bash
# Fix the syntax error in run-unlimited-test.sh

echo "# 🔧 Fixing Script Syntax Error"
echo "=============================="
echo ""

echo "## Current Issue"
echo "--------------"
echo "Syntax error near line 58 - likely from sed replacement"
echo ""

# Backup current script
cp run-unlimited-test.sh run-unlimited-test.sh.backup

echo "## Fixing the Script"
echo "------------------"
cat > run-unlimited-test.sh << 'SCRIPT'
#!/bin/bash
# Run NeuroSploit with Claude Sonnet (UPDATED PROMPT)

set -e

echo "=========================================="
echo "NeuroSploit Claude Sonnet Test"
echo "Cloud API - Anthropic - UPDATED PROMPT"
echo "=========================================="

# Configuration
LLM_API_BASE="${LLM_API_BASE:-https://api.anthropic.com/v1}"
LLM_MODEL="${LLM_MODEL:-claude-sonnet-4-20250514}"
TARGET="${TARGET:-10.0.2.20}"
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}"

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "ERROR: ANTHROPIC_API_KEY environment variable not set"
    echo "Please set it with: export ANTHROPIC_API_KEY='sk-ant-...'"
    exit 1
fi

echo "Target: $TARGET (DVWA)"
echo "Model: $LLM_MODEL"
echo "Mode: AUTONOMOUS (40 iterations)"
echo "Timeout: 300s per LLM call"
echo "Context: 32768 tokens"
echo ""
echo "🔥 NEW: System prompt updated with tool installation instructions!"
echo ""

# Build image if needed
docker build -t neurosploit-kali:minimal -f ../kali-executor/Dockerfile.minimal ../kali-executor 2>&1 | tail -3

echo ""
echo "Starting autonomous test..."
echo "Starting unlimited autonomous test..."
echo "This will run until the agent completes all exploitation"
echo "=========================================="

# Run with unlimited iterations
docker run -it \
  --name neurosploit-pentest-$(date +%Y%m%d_%H%M%S) \
  --network vulnerable-lab_dmz \
  -e LLM_API_BASE="$LLM_API_BASE" \
  -e LLM_MODEL="$LLM_MODEL" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e TARGET="$TARGET" \
  -v "$(pwd)/logs:/pentest/logs" \
  -v "$(pwd)/extracted:/root/extracted" \
  -v "$(pwd)/../kali-executor/open-interpreter:/opt/neurosploit" \
  neurosploit-kali:minimal \
  python3 /opt/neurosploit/dynamic_agent.py \
  --target "$TARGET" \
  --max-iterations 40 \
  --objective "Full autonomous penetration test - exploit ALL vulnerabilities, extract ALL credentials, access ALL databases, perform lateral movement, and exfiltrate ALL sensitive data. Do not stop until complete." 2>&1 | tee logs/claude_resume.log

echo ""
echo "=========================================="
echo "Test Complete"
echo "=========================================="
echo "Logs: ./logs/"
echo "Check logs/COMPREHENSIVE_REPORT_*.md for findings"
SCRIPT

echo "✅ Script fixed!"
echo ""

echo "## Running Claude Test"
echo "===================="
echo ""
./run-unlimited-test.sh

