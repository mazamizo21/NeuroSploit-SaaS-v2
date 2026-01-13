#!/bin/bash
# Extract all passwords and credentials from execution logs

echo "# 🔑 PASSWORDS & CREDENTIALS FOUND"
echo "=================================="
echo ""

echo "## MySQL Root Password"
echo "```"
grep -E "root.*p@ssw0rd|p@ssw0rd" logs/agent_executions.jsonl | jq -r 'select(.success == true) | .content' | grep -o "p@ssw0rd" | head -1
echo "```"
echo ""
echo "**Target:** 10.0.2.20"
echo "**Username:** root"
echo "**Password:** p@ssw0rd"
echo ""

echo "## All Database Connection Commands"
echo "```bash"
grep "mysql.*-p" logs/agent_executions.jsonl | jq -r 'select(.success == true) | .content' | grep -E "mysql.*-p" | head -5
echo "```"
echo ""

echo "## Files Created by AI (in container)"
echo "```"
echo "/root/2026-01-12_06-46-52.zip"
echo "/root/2026-01-12_08-51-31.zip"
echo "/root/flags.txt"
echo "/root/mysql_databases.txt"
echo "/root/nmap/*.nmap"
echo "```"
echo ""

echo "## To Access These Files:"
echo "1. The files were created inside the Docker container at /root/"
echo "2. The container was removed after completion (--rm flag)"
echo "3. To preserve files next time, modify run-unlimited-test.sh:"
echo ""
echo "   Add this volume mount:"
echo "   -v \"\$(pwd)/extracted:/root/extracted\" \\"
echo ""
echo "   Then in the agent, copy files to /root/extracted/"
echo ""

