#!/bin/bash
# Check current system prompt for tool installation instructions

echo "# 🔍 Current System Prompt Analysis"
echo "===================================="
echo ""

echo "## Current System Prompt (lines 76-93):"
echo "---------------------------------------"
grep -A 20 "SYSTEM_PROMPT_BASE" ../kali-executor/open-interpreter/dynamic_agent.py | head -25
echo ""

echo "## What's Missing?"
echo "------------------"
echo ""
echo "❌ NO instruction about installing missing tools"
echo "❌ NO mention of apt-get or package management"
echo "❌ NO guidance on handling 'command not found' errors"
echo ""

echo "## Your Hypothesis is CORRECT!"
echo "------------------------------"
echo ""
echo "The AI is given examples like:"
echo '  - mysql -h TARGET -u USERNAME -p'"'"'PASSWORD'"'"' -e "SHOW DATABASES;"'
echo ""
echo "But when mysql returns 'command not found', the AI has NO instruction to:"
echo "  1. Recognize this means the tool is missing"
echo "  2. Install it with: apt-get update && apt-get install -y default-mysql-client"
echo "  3. Retry the command"
echo ""

echo "## What We Should Add:"
echo "---------------------"
echo ""
echo "Explicit instructions like:"
echo '```'
echo "IMPORTANT: If a command fails with 'command not found' (exit code 127):"
echo "  1. Install the missing tool immediately"
echo "  2. You have root access - use apt-get without sudo"
echo "  3. Example: apt-get update && apt-get install -y <package-name>"
echo "  4. Common packages:"
echo "     - mysql-client or default-mysql-client for MySQL"
echo "     - postgresql-client for PostgreSQL"
echo "     - sshpass for SSH with passwords"
echo "  5. Then retry your original command"
echo '```'
echo ""

