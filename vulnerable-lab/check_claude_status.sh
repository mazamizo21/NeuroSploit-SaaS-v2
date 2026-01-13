#!/bin/bash
# Check Claude's current status and logs

echo "# 🤖 Claude Sonnet Status Check"
echo "==============================="
echo ""

# Find Claude's log files
CLAUDE_LOG=$(ls -t logs/claude*.log 2>/dev/null | head -1)
CLAUDE_REPORT=$(ls -t logs/COMPREHENSIVE_REPORT_*claude*.md 2>/dev/null | head -1)

if [ -z "$CLAUDE_LOG" ]; then
    echo "❌ No Claude log files found"
    echo ""
    echo "Available logs:"
    ls -la logs/ 2>/dev/null | grep -E "\.log$|\.md$" | head -10
    exit 1
fi

echo "## Claude's Last Test"
echo "-------------------"
echo "Log file: $CLAUDE_LOG"
echo ""

echo "## Final Status"
echo "--------------"
tail -20 "$CLAUDE_LOG" | grep -E "ENGAGEMENT COMPLETE|Iterations:|Executions:|Rate limit" | tail -5
echo ""

echo "## Where Claude Left Off"
echo "-----------------------"
tail -50 "$CLAUDE_LOG" | grep -E "Iteration|mysql|apt-get|Exit:" | tail -10
echo ""

if [ -f "$CLAUDE_REPORT" ]; then
    echo "## Claude's Achievements"
echo "------------------------"
    echo "From comprehensive report:"
    grep -A 10 "Executive Summary" "$CLAUDE_REPORT" 2>/dev/null | head -15
    echo ""
fi

echo "## Can We Resume?"
echo "----------------"
echo ""
echo "Claude's test was stopped by rate limit, not failure."
echo "To resume:"
echo "  1. Wait for rate limit to reset (usually 1-5 minutes)"
echo "  2. Run: ./run-unlimited-test.sh"
echo "  3. Claude will continue from where it left off"
echo ""

