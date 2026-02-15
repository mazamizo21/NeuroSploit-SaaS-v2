#!/bin/bash
# Analyze Claude Sonnet test results

echo "# 🤖 Claude Sonnet Test Results"
echo "================================"
echo ""

echo "## Test Summary"
echo "--------------"
echo "Status: STOPPED - Rate limit exceeded"
echo "Iterations: 6/35"
echo "Executions: 72 (60 successful)"
echo "Success Rate: 83%"
echo "Duration: ~4 minutes"
echo ""

echo "## What Happened?"
echo "-----------------"
echo ""
echo "Claude hit Anthropic's rate limit:"
echo "  - Limit: 30,000 input tokens per minute"
echo "  - Iterations 1-5 consumed tokens rapidly"
echo "  - Iteration 6 exceeded the limit"
echo ""

echo "## What Claude Accomplished in 6 Iterations"
echo "-------------------------------------------"
echo ""
echo "Tools used: nmap, dirb, nikto, hydra, ffuf, arp-scan, wapiti, mysql, curl, gobuster, sqlmap"
echo ""
echo "Let's check the comprehensive report:"
echo ""
cat logs/COMPREHENSIVE_REPORT_*.md
echo ""

echo "## Detailed Execution Log Analysis"
echo "----------------------------------"
echo ""
jq -r 'select(.iteration <= 6) | "[\(.iteration)] \(.content[:150]) | Exit: \(.exit_code)"' logs/agent_executions.jsonl 2>/dev/null | head -30
echo ""

