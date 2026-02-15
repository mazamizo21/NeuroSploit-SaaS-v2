#!/bin/bash
# WhiteRabbitNeo-13B Test with Updated Prompt

echo "# 🐰 WhiteRabbitNeo-13B Test - UPDATED PROMPT"
echo "=========================================="
echo ""

echo "## What Changed?"
echo "--------------"
echo "✅ System prompt now includes explicit tool installation instructions"
echo "✅ When AI sees exit code 127, it will install the missing tool"
echo "✅ No more sudo issues - uses apt-get directly"
echo ""

echo "## Expected Behavior"
echo "-------------------"
echo "WhiteRabbitNeo should now:"
echo "  1. Try mysql command"
echo "  2. Get exit 127 (command not found)"
echo "  3. Install: apt-get update && apt-get install -y default-mysql-client"
echo "  4. Retry mysql command"
echo "  5. Connect successfully!"
echo ""

echo "## Comparison: Before vs After"
echo "----------------------------"
echo "BEFORE (40 iterations):"
echo "  ❌ Got stuck trying 'sudo apt-get install'"
echo "  ❌ Never installed mysql-client"
echo "  ❌ Failed to connect to database"
echo ""
echo "AFTER (expecting):"
echo "  ✅ Install mysql-client automatically"
echo "  ✅ Connect to MySQL"
echo "  ✅ Extract credentials and flags"
echo ""

echo "## Starting Test..."
echo "=================="
echo ""

