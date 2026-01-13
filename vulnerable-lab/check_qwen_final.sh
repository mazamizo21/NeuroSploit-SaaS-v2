#!/bin/bash
# Check Qwen3-Next-80B final results

echo "# 📊 Qwen3-Next-80B Final Results Check"
echo "======================================="
echo ""

# Find the Qwen log files
QWEN_LOG=$(ls -t logs/*qwen*.log 2>/dev/null | head -1)
QWEN_JSONL=$(ls -t logs/agent_executions.jsonl 2>/dev/null | head -1)

if [ -z "$QWEN_LOG" ]; then
    echo "❌ No Qwen log files found"
    exit 1
fi

echo "## Test Status"
echo "-------------"
tail -20 "$QWEN_LOG" | grep -E "Iteration|ENGAGEMENT COMPLETE|Executions" | tail -10
echo ""

echo "## Final Iteration Reached"
echo "-------------------------"
LAST_ITER=$(grep "=== Iteration" "$QWEN_LOG" | tail -1)
echo "$LAST_ITER"
echo ""

echo "## Did Qwen Complete or Get Stuck?"
echo "----------------------------------"
if grep -q "ENGAGEMENT COMPLETE" "$QWEN_LOG"; then
    echo "✅ Test completed"
    grep "Iterations:" "$QWEN_LOG" | tail -1
    grep "Executions:" "$QWEN_LOG" | tail -1
else
    echo "⚠️ Test was interrupted or still running"
fi
echo ""

echo "## Key Actions in Final Iterations"
echo "----------------------------------"
if [ -f "$QWEN_JSONL" ]; then
    # Get last 10 iterations
    LAST_ITERS=$(jq -r '.iteration' "$QWEN_JSONL" 2>/dev/null | sort -u | tail -10)
    for iter in $LAST_ITERS; do
        echo "Iteration $iter:"
        jq -r "select(.iteration == $iter) | \"  [\(.exit_code)] \(.content[:100])...\"" "$QWEN_JSONL" 2>/dev/null | head -3
        echo ""
    done
fi

