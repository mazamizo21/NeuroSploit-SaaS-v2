#!/bin/bash
# Comprehensive audit of ALL agent files for hardcoded information

echo "# 🔍 COMPREHENSIVE SECURITY AUDIT - ALL AGENT FILES"
echo "===================================================="
echo ""

AGENT_DIR="/Users/tazjack/Documents/PenTest/TazoSploit--v2/kali-executor/open-interpreter"

echo "## 1. SEARCHING FOR HARDCODED PASSWORDS"
echo "----------------------------------------"
echo ""
echo "### Checking all Python files for password patterns:"
grep -rn "password.*=.*['\"]" "$AGENT_DIR"/*.py | grep -v "MYSQL_ROOT_PASSWORD\|DB_PASSWORD" | grep -v "def \|class \|#" || echo "✅ No hardcoded password assignments found"
echo ""

echo "### Checking for specific password strings:"
grep -rn "p@ssw0rd\|admin123\|password123\|secret123" "$AGENT_DIR"/*.py || echo "✅ No specific passwords found"
echo ""

echo "## 2. SEARCHING FOR HARDCODED CREDENTIALS"
echo "----------------------------------------"
echo ""
grep -rn "username.*=.*['\"]root\|user.*=.*['\"]admin" "$AGENT_DIR"/*.py | grep -v "def \|class \|#" || echo "✅ No hardcoded usernames found"
echo ""

echo "## 3. SEARCHING FOR HARDCODED TARGET INFO"
echo "----------------------------------------"
echo ""
echo "### IP addresses:"
grep -rn "10\.0\.2\.\|192\.168\.\|target.*=.*['\"]" "$AGENT_DIR"/*.py | grep -v "def \|class \|#\|TARGET" || echo "✅ No hardcoded IPs found"
echo ""

echo "### Target-specific strings:"
grep -rn "dvwa\|damn.*vulnerable\|metasploitable" "$AGENT_DIR"/*.py -i || echo "✅ No target-specific references found"
echo ""

echo "## 4. SEARCHING FOR HARDCODED EXPLOIT COMMANDS"
echo "----------------------------------------------"
echo ""
grep -rn "sqlmap.*-u.*http\|hydra.*ssh\|msfconsole.*exploit" "$AGENT_DIR"/*.py || echo "✅ No hardcoded exploit commands found"
echo ""

echo "## 5. CHECKING SYSTEM PROMPTS IN ALL FILES"
echo "-------------------------------------------"
echo ""
for file in "$AGENT_DIR"/*.py; do
    if grep -q "SYSTEM_PROMPT\|system_prompt\|PROMPT" "$file"; then
        echo "### Found in: $(basename $file)"
        grep -A 30 "SYSTEM_PROMPT.*=\|system_prompt.*=" "$file" | head -35
        echo ""
    fi
done
echo ""

echo "## 6. CHECKING FOR HINTS IN COMMENTS"
echo "-------------------------------------"
echo ""
grep -rn "# .*password.*root\|# .*admin.*123\|# .*try.*p@ss" "$AGENT_DIR"/*.py || echo "✅ No password hints in comments"
echo ""

echo "## 7. CHECKING CONFIGURATION FILES"
echo "-----------------------------------"
echo ""
if [ -f "$AGENT_DIR/config.py" ]; then
    echo "### config.py contents:"
    cat "$AGENT_DIR/config.py"
    echo ""
fi
echo ""

echo "## 8. ANALYZING EXECUTION LOGS FOR DISCOVERY METHOD"
echo "----------------------------------------------------"
echo ""
echo "### How did AI get the password? Checking first 10 iterations:"
grep "p@ssw0rd\|mysql.*root" /Users/tazjack/Documents/PenTest/TazoSploit--v2/vulnerable-lab/logs/agent_executions.jsonl 2>/dev/null | jq -r 'select(.iteration <= 10) | "Iteration \(.iteration): \(.content[:200])"' | head -10
echo ""

