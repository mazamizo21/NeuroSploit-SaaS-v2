#!/bin/bash
# Extract evidence of successful exploits, credentials, and access

echo "=== EVIDENCE COLLECTION REPORT ==="
echo "Generated: $(date)"
echo ""

# 1. Extract successful commands with credentials
echo "## 1. CREDENTIALS EXTRACTED"
echo "================================"
grep -E "password|MYSQL_ROOT_PASSWORD|DB_PASSWORD|user.*root" logs/agent_executions.jsonl | \
  jq -r 'select(.success == true) | "[\(.timestamp)] \(.content[:100])\nOutput: \(.stdout[:200])\n"' 2>/dev/null | head -20
echo ""

# 2. Extract database access evidence
echo "## 2. DATABASE ACCESS EVIDENCE"
echo "================================"
grep -E "mysql|psql|mariadb" logs/agent_executions.jsonl | \
  jq -r 'select(.success == true and .exit_code == 0) | "[\(.timestamp)] Command: \(.content[:150])\nResult: \(.stdout[:300])\n---"' 2>/dev/null | head -30
echo ""

# 3. Extract /etc/passwd access (system file access proof)
echo "## 3. SYSTEM FILE ACCESS (/etc/passwd)"
echo "================================"
grep "cat /etc/passwd" logs/agent_executions.jsonl | \
  jq -r 'select(.success == true) | "[\(.timestamp)] Successfully read /etc/passwd\nUsers found: \(.stdout | split("\n") | length) users\nFirst 5 users:\n\(.stdout | split("\n")[:5] | join("\n"))\n"' 2>/dev/null | head -1
echo ""

# 4. Extract SSH/shell connection attempts
echo "## 4. SSH/SHELL CONNECTION EVIDENCE"
echo "================================"
grep -E "ssh|sshpass|nc -e|bash -i" logs/agent_executions.jsonl | \
  jq -r 'select(.success == true) | "[\(.timestamp)] \(.content[:200])\nExit: \(.exit_code)\n---"' 2>/dev/null | head -10
echo ""

# 5. Extract nmap scan results
echo "## 5. NETWORK RECONNAISSANCE"
echo "================================"
grep "nmap" logs/agent_executions.jsonl | \
  jq -r 'select(.success == true and (.stdout | length) > 100) | "[\(.timestamp)] Scan completed\nPorts found:\n\(.stdout[:500])\n---"' 2>/dev/null | head -5
echo ""

# 6. Count successful vs failed executions
echo "## 6. EXECUTION STATISTICS"
echo "================================"
TOTAL=$(wc -l < logs/agent_executions.jsonl)
SUCCESS=$(grep '"success": true' logs/agent_executions.jsonl | wc -l)
FAILED=$(grep '"success": false' logs/agent_executions.jsonl | wc -l)
echo "Total executions: $TOTAL"
echo "Successful: $SUCCESS"
echo "Failed: $FAILED"
echo "Success rate: $(echo "scale=2; $SUCCESS * 100 / $TOTAL" | bc)%"
echo ""

# 7. Extract unique tools used
echo "## 7. TOOLS USED"
echo "================================"
jq -r '.tool_used' logs/agent_executions.jsonl 2>/dev/null | sort | uniq -c | sort -rn | head -15
echo ""

# 8. Extract any found flags or sensitive data
echo "## 8. FLAGS & SENSITIVE DATA"
echo "================================"
grep -iE "flag|password.*found|secret|token" logs/agent_executions.jsonl | \
  jq -r 'select(.success == true) | "[\(.timestamp)] \(.content[:100])\n\(.stdout[:200])\n---"' 2>/dev/null | head -10

