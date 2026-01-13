#!/bin/bash
# Check if Claude tried MySQL and installed it

LOG_FILE="logs/agent_executions.jsonl"

echo "# 🎯 CRITICAL QUESTION: Did Claude Install MySQL Client?"
echo "========================================================"
echo ""

echo "## 1. Did Claude Try to Use MySQL?"
echo "----------------------------------"
jq -r 'select(.content | contains("mysql")) | "[\(.iteration)] \(.content[:150]) | Exit: \(.exit_code)"' "$LOG_FILE" 2>/dev/null
echo ""

echo "## 2. Did Claude Install MySQL Client?"
echo "--------------------------------------"
jq -r 'select(.content | contains("mysql-client") or contains("default-mysql-client")) | "[\(.iteration)] \(.content[:200])"' "$LOG_FILE" 2>/dev/null
echo ""

echo "## 3. What Tools Did Claude Install?"
echo "------------------------------------"
jq -r 'select(.content | contains("apt-get install")) | "[\(.iteration)] \(.content[:200])"' "$LOG_FILE" 2>/dev/null
echo ""

echo "## 4. Summary"
echo "------------"
echo ""
MYSQL_ATTEMPTS=$(jq -r 'select(.content | contains("mysql"))' "$LOG_FILE" 2>/dev/null | wc -l)
MYSQL_INSTALLS=$(jq -r 'select(.content | contains("mysql-client") or contains("default-mysql-client"))' "$LOG_FILE" 2>/dev/null | wc -l)

echo "MySQL command attempts: $MYSQL_ATTEMPTS"
echo "MySQL client installations: $MYSQL_INSTALLS"
echo ""

if [ "$MYSQL_INSTALLS" -gt 0 ]; then
    echo "✅ SUCCESS! Claude installed mysql-client with the new prompt!"
else
    echo "❌ Claude did not install mysql-client"
fi

