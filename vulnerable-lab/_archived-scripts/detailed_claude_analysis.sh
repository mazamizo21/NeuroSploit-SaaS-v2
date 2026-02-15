#!/bin/bash
# Detailed analysis of Claude's 6 iterations

LOG_FILE="logs/agent_executions.jsonl"

echo "# �� Claude Sonnet Detailed Analysis (6 Iterations)"
echo "===================================================="
echo ""

echo "## Iteration Breakdown"
echo "---------------------"
echo ""

for i in {1..6}; do
    echo "### Iteration $i"
    echo ""
    
    # Count commands in this iteration
    CMD_COUNT=$(jq -r "select(.iteration == $i)" "$LOG_FILE" 2>/dev/null | wc -l)
    SUCCESS_COUNT=$(jq -r "select(.iteration == $i and .success == true)" "$LOG_FILE" 2>/dev/null | wc -l)
    
    echo "Commands executed: $CMD_COUNT"
    echo "Successful: $SUCCESS_COUNT"
    echo ""
    
    # Show key commands
    echo "Key actions:"
    jq -r "select(.iteration == $i) | \"  - \(.content[:100])... | Exit: \(.exit_code)\"" "$LOG_FILE" 2>/dev/null | head -5
    echo ""
done

echo "## Critical Question: Did Claude Try to Access MySQL?"
echo "-----------------------------------------------------"
echo ""
jq -r 'select(.content | contains("mysql")) | "[\(.iteration)] \(.content[:150]) | Exit: \(.exit_code)"' "$LOG_FILE" 2>/dev/null
echo ""

echo "## Did Claude Try to Install Missing Tools?"
echo "--------------------------------------------"
echo ""
jq -r 'select(.content | contains("apt-get") or contains("apt install")) | "[\(.iteration)] \(.content[:150])"' "$LOG_FILE" 2>/dev/null
echo ""

echo "## What Credentials Did Claude Extract?"
echo "----------------------------------------"
echo ""
jq -r 'select(.stdout | length > 50) | select(.stdout | contains("user") or contains("pass") or contains("root")) | "[\(.iteration)] Found in output:\n\(.stdout[:300])\n---"' "$LOG_FILE" 2>/dev/null | head -20
echo ""

echo "## Rate Limit Details"
echo "--------------------"
echo ""
echo "From the error message:"
echo "  - Organization limit: 30,000 input tokens per minute"
echo "  - Tokens consumed in 6 iterations: 67,596 total"
echo "  - Average per iteration: ~11,266 tokens"
echo "  - Claude generates VERY detailed responses"
echo ""
echo "This is actually a GOOD sign - Claude is thinking deeply!"
echo ""

