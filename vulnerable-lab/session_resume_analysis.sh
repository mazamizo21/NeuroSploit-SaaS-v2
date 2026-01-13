#!/bin/bash
# Analyze session resume capability

echo "# �� Session Resume Analysis"
echo "=========================="
echo ""

echo "## SURPRISE! Session Resume Code EXISTS!"
echo "--------------------------------------"
echo ""
grep -A 15 "def load_session" ../kali-executor/open-interpreter/dynamic_agent.py
echo ""

echo "## The Issue: Resume Not Called"
echo "------------------------------"
echo ""
echo "The agent HAS a load_session() method but:"
echo "  ❌ It's never called in __init__"
echo "  ❌ No auto-resume logic"
echo "  ❌ Always creates new session_id"
echo ""

echo "## Current __init__ Logic"
echo "------------------------"
echo ""
grep -A 5 "session_id.*or" ../kali-executor/open-interpreter/dynamic_agent.py
echo ""

echo "## What Should Happen"
echo "-------------------"
echo ""
echo "The agent should:"
echo "  1. Check for latest session file"
echo "  2. Call load_session() if found"
echo "  3. Continue from saved iteration"
echo ""
echo "But it doesn't!"
echo ""

echo "## Session Files Available"
echo "-------------------------"
echo ""
ls -la logs/session_*.json 2>/dev/null | tail -3
echo ""

if [ -f "logs/session_session_20260112_164953.json" ]; then
    echo "## Last Session Details"
echo "----------------------"
    echo "File: logs/session_session_20260112_164953.json"
    echo "Size: $(du -h logs/session_session_20260112_164953.json | cut -f1)"
    echo ""
    echo "Contains iteration: $(jq -r '.iteration' logs/session_session_20260112_164953.json 2>/dev/null || echo 'unknown')"
    echo "Contains executions: $(jq '.executions | length' logs/session_session_20260112_164953.json 2>/dev/null || echo 'unknown')"
    echo ""
fi

echo "## Conclusion"
echo "------------"
echo ""
echo "You're ABSOLUTELY right!"
echo ""
echo "✅ Session SAVE code exists"
echo "✅ Session LOAD code exists"
echo "❌ Resume LOGIC doesn't exist"
echo ""
echo "The agent can save and load sessions"
echo "But never attempts to resume automatically"
echo ""

echo "This is a missed feature for true persistence!"
echo ""

