#!/bin/bash
# Trace EXACTLY where and when the AI got the password

LOG_FILE="/Users/tazjack/Documents/PenTest/TazoSploit--v2/vulnerable-lab/logs/agent_executions.jsonl"

echo "# 🔬 DETAILED PASSWORD SOURCE TRACE"
echo "===================================="
echo ""

echo "## ITERATION 1 - All Commands"
echo "-----------------------------"
jq -r 'select(.iteration == 1) | "[\(.timestamp)] Tool: \(.tool_used)\nCommand: \(.content[:300])\nStdout: \(.stdout[:200])\nSuccess: \(.success)\n---"' "$LOG_FILE" 2>/dev/null
echo ""

echo "## ITERATION 2 - All Commands"
echo "-----------------------------"
jq -r 'select(.iteration == 2) | "[\(.timestamp)] Tool: \(.tool_used)\nCommand: \(.content[:300])\nStdout: \(.stdout[:200])\nSuccess: \(.success)\n---"' "$LOG_FILE" 2>/dev/null
echo ""

echo "## WHEN DID MYSQL CONNECTION SUCCEED?"
echo "-------------------------------------"
jq -r 'select(.content | contains("mysql")) | select(.success == true and (.stdout | length) > 10) | "Iteration \(.iteration): SUCCESS\nCommand: \(.content[:200])\nOutput: \(.stdout[:300])\n---"' "$LOG_FILE" 2>/dev/null | head -20
echo ""

echo "## DID AI EVER FIND THE PASSWORD IN A FILE?"
echo "--------------------------------------------"
jq -r 'select(.content | contains("grep") or contains("cat") or contains("find")) | select(.stdout | contains("p@ssw0rd") or contains("password")) | "Iteration \(.iteration):\nCommand: \(.content[:200])\nFound: \(.stdout[:200])\n---"' "$LOG_FILE" 2>/dev/null
echo ""

