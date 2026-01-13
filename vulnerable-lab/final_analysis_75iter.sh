#!/bin/bash
# Complete analysis of 75-iteration test

LOG_FILE="logs/agent_executions.jsonl"

echo "# 📊 FINAL ANALYSIS - 75 Iteration Test"
echo "========================================"
echo ""

echo "## 1. WHERE DID 'dvwa_user:dvwa_pass' COME FROM?"
echo "-------------------------------------------------"
echo ""
echo "First appearance of dvwa credentials:"
jq -r 'select(.content | contains("dvwa_user") or contains("dvwa_pass")) | "[\(.iteration)] \(.content[:250])"' "$LOG_FILE" | head -3
echo ""

echo "## 2. DID AI EVER SUCCESSFULLY CONNECT TO MYSQL?"
echo "-------------------------------------------------"
echo ""
echo "Checking for successful MySQL connections with actual output:"
jq -r 'select(.content | contains("mysql -h 10.0.2.20")) | select(.exit_code == 0 and (.stdout | length) > 50) | "[\(.iteration)] SUCCESS\nCommand: \(.content[:200])\nOutput: \(.stdout[:300])\n---"' "$LOG_FILE" | head -10
echo ""

echo "## 3. WHY DID MYSQL COMMANDS FAIL?"
echo "-----------------------------------"
echo ""
echo "Exit code 127 means 'command not found' - mysql client not installed"
echo ""
echo "Checking when mysql was available:"
jq -r 'select(.content | contains("mysql -h")) | "[\(.iteration)] Exit: \(.exit_code) | Stderr: \(.stderr[:80])"' "$LOG_FILE" | head -10
echo ""

echo "## 4. DID AI EVER INSTALL MYSQL CLIENT?"
echo "----------------------------------------"
echo ""
jq -r 'select(.content | contains("apt-get") or contains("apt install")) | select(.content | contains("mysql") or contains("mariadb")) | "[\(.iteration)] \(.content[:200])\nSuccess: \(.success)"' "$LOG_FILE"
echo ""

echo "## 5. WHAT DID AI ACTUALLY ACCOMPLISH?"
echo "---------------------------------------"
echo ""
cat logs/COMPREHENSIVE_REPORT_*.md
echo ""

