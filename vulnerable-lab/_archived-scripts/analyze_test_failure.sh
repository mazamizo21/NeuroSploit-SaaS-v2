#!/bin/bash
# Analyze why the test didn't perform exploits

LOG_FILE="logs/agent_executions.jsonl"

echo "# 🔍 TEST FAILURE ANALYSIS"
echo "=========================="
echo ""

echo "## 1. DID AI INSTALL MYSQL CLIENT?"
echo "-----------------------------------"
jq -r 'select(.content | contains("apt-get") or contains("mariadb-client") or contains("mysql-client")) | "[\(.iteration)] \(.content[:200])\nSuccess: \(.success)\nStdout: \(.stdout[:200])"' "$LOG_FILE" | head -20
echo ""

echo "## 2. DID AI TRY TO CONNECT TO MYSQL?"
echo "--------------------------------------"
jq -r 'select(.content | contains("mysql -h 10.0.2.20")) | "[\(.iteration)] \(.content[:200])\nExit: \(.exit_code)\nSuccess: \(.success)"' "$LOG_FILE" | head -20
echo ""

echo "## 3. WHAT DID AI DO IN EARLY ITERATIONS?"
echo "-------------------------------------------"
jq -r 'select(.iteration <= 5) | "[\(.iteration)] \(.content[:200])\nSuccess: \(.success)"' "$LOG_FILE" | head -30
echo ""

echo "## 4. DID AI GET STUCK IN A LOOP?"
echo "-----------------------------------"
echo "Checking for repeated commands:"
jq -r '.content[:100]' "$LOG_FILE" | sort | uniq -c | sort -rn | head -10
echo ""

echo "## 5. WHAT WAS AI TRYING IN FINAL ITERATIONS?"
echo "----------------------------------------------"
jq -r 'select(.iteration >= 20) | "[\(.iteration)] \(.content[:150])"' "$LOG_FILE" | head -20
echo ""

