#!/bin/bash
# Deep analysis of what AI actually tried

LOG_FILE="logs/agent_executions.jsonl"

echo "# 🔬 DEEP DIVE: What Did AI Actually Try?"
echo "=========================================="
echo ""

echo "## ITERATION 2 - CRITICAL MOMENT"
echo "--------------------------------"
echo ""
echo "AI tried 'dvwa_user:dvwa_pass' in iteration 2!"
echo ""
jq -r 'select(.iteration == 2) | select(.content | contains("dvwa")) | "Command: \(.content[:300])\n\nExit Code: \(.exit_code)\nSuccess: \(.success)\nStdout: \(.stdout[:200])\nStderr: \(.stderr[:200])\n---"' "$LOG_FILE"
echo ""

echo "## WHERE DID 'dvwa_user:dvwa_pass' COME FROM?"
echo "----------------------------------------------"
echo ""
echo "Checking iteration 1 for any hints..."
jq -r 'select(.iteration == 1) | "[\(.iteration)] \(.content[:200])"' "$LOG_FILE"
echo ""

echo "## DID MYSQL CLIENT EXIST IN ITERATION 2?"
echo "------------------------------------------"
echo ""
jq -r 'select(.iteration == 2) | select(.content | contains("mysql")) | "Exit: \(.exit_code) | Stderr: \(.stderr[:100])"' "$LOG_FILE" | head -3
echo ""

echo "## WHEN WAS MYSQL CLIENT INSTALLED?"
echo "------------------------------------"
echo ""
jq -r 'select(.content | contains("apt-get install") and contains("mysql")) | "[\(.iteration)] \(.content[:150])\nSuccess: \(.success)"' "$LOG_FILE" | head -5
echo ""

echo "## AFTER MYSQL INSTALLED, DID AI RETRY dvwa_user?"
echo "--------------------------------------------------"
echo ""
jq -r 'select(.iteration >= 6) | select(.content | contains("dvwa_user") or contains("dvwa_pass")) | "[\(.iteration)] \(.content[:200])"' "$LOG_FILE" | head -10
echo ""

echo "## TOTAL EXECUTIONS"
echo "------------------"
echo ""
TOTAL=$(wc -l < "$LOG_FILE")
echo "Total command executions: $TOTAL"
echo "Current iteration: 74/75"
echo "Commands per iteration: ~$(echo "$TOTAL / 74" | bc)"
echo ""

