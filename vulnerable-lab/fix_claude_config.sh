#!/bin/bash
# Fix Claude configuration issues

echo "# 🔧 Fixing Claude Configuration"
echo "================================"
echo ""

echo "## Issue 1: Session File Path"
echo "---------------------------"
echo ""
echo "The session file exists but path mismatch:"
echo "Host: logs/session_session_20260112_164953.json"
echo "Container: /pentest/logs/session_20260112_164953.json"
echo ""
echo "The auto-resume is looking for: session_20260112_164953"
echo "But file is named: session_session_20260112_164953"
echo ""

echo "## Issue 2: LLM Provider Auto-Detection"
echo "-------------------------------------"
echo ""
echo "The --llm-provider auto is causing issues"
echo "Let's remove it and use direct configuration"
echo ""

echo "## Fixing the Script"
echo "------------------"
echo ""

# Update script to remove auto provider and fix session naming
sed -i '' 's/--llm-provider auto//' run-unlimited-test.sh

echo "✅ Removed --llm-provider auto"
echo ""

echo "## Updated Script"
echo "---------------"
grep -A 5 "python3 /opt/tazosploit" run-unlimited-test.sh
echo ""

echo "## Session File Naming Issue"
echo "--------------------------"
echo ""
echo "The session files have double 'session_' prefix:"
echo "Expected: session_20260112_164953.json"
echo "Actual: session_session_20260112_164953.json"
echo ""
echo "This is why auto-resume can't find it"
echo ""

echo "## Quick Fix: Rename Session File"
echo "--------------------------------"
echo ""
if [ -f "logs/session_session_20260112_164953.json" ]; then
    cp logs/session_session_20260112_164953.json logs/session_20260112_164953.json
    echo "✅ Created copy with correct naming"
    echo "Now auto-resume should find it"
else
    echo "❌ Session file not found"
fi
echo ""

echo "## Ready to Test Again"
echo "---------------------"
echo ""
echo "Fixed issues:"
echo "  ✅ Removed --llm-provider auto"
echo "  ✅ Fixed session file naming"
echo "  ✅ Session file accessible"
echo ""
echo "Run again:"
echo "  ./run-unlimited-test.sh"
echo ""

