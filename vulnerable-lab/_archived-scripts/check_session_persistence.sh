#!/bin/bash
# Check session persistence implementation

echo "# 🗂️ Session Persistence Analysis"
echo "================================="
echo ""

echo "## Current Session Implementation"
echo "--------------------------------"
echo ""
grep -A 10 -B 5 "session" ../kali-executor/open-interpreter/dynamic_agent.py | head -20
echo ""

echo "## What Session Persistence Should Do"
echo "------------------------------------"
echo ""
echo "Session persistence should save:"
echo "  1. Conversation history (LLM interactions)"
echo "  2. Execution history (commands run)"
echo "  3. Current iteration number"
echo "  4. Discovered credentials/flags"
echo "  5. Tool installation state"
echo ""

echo "## Checking Saved Sessions"
echo "-------------------------"
echo ""
ls -la logs/ | grep session
echo ""

if [ -f "logs/session_session_20260112_164953.json" ]; then
    echo "## Session File Contents"
    echo "----------------------"
    echo "Last session saved:"
    jq -r '.iteration' logs/session_session_20260112_164953.json 2>/dev/null | tail -1
    echo ""
    echo "Session size:"
    du -h logs/session_session_20260112_164953.json 2>/dev/null
    echo ""
fi

echo "## Problem: Session Save vs Resume"
echo "---------------------------------"
echo ""
echo "❌ The agent SAVES sessions but doesn't RESUME from them"
echo ""
echo "What happens:"
echo "  1. Agent runs and saves session to JSON"
echo "  2. Agent stops (rate limit/error)"
echo "  3. New run starts FRESH - doesn't load saved session"
echo "  4. Starts from iteration 1 again"
echo ""

echo "## What's Missing for True Resume"
echo "----------------------------------"
echo ""
echo "To enable resume, the agent needs:"
echo "  1. Check for existing session file on startup"
echo "  2. Load conversation history"
echo "  3. Load execution history"
echo "  4. Set current iteration from saved state"
echo "  5. Continue from where it left off"
echo ""

echo "## Current Implementation"
echo "------------------------"
echo ""
echo "The agent only:"
echo "  ✅ Saves session at end"
echo "  ✅ Saves comprehensive report"
echo "  ❌ Does NOT resume from saved session"
echo "  ❌ Always starts fresh"
echo ""

echo "## Conclusion"
echo "------------"
echo ""
echo "You're right - we have session PERSISTENCE (saving)"
echo "But we don't have session RESUME capability"
echo ""
echo "The agent saves its state but can't reload it"
echo "Each run starts from scratch"
echo ""

