#!/bin/bash
# Show the session save/load code

echo "# 📄 Session Implementation Code"
echo "==============================="
echo ""

echo "## Session Save Code"
echo "------------------"
grep -A 20 "Session saved" ../kali-executor/open-interpreter/dynamic_agent.py
echo ""

echo "## Session ID Generation"
echo "----------------------"
grep -A 5 -B 5 "session_id.*or" ../kali-executor/open-interpreter/dynamic_agent.py
echo ""

echo "## What's Missing: Resume Logic"
echo "------------------------------"
echo ""
echo "The agent needs code like:"
echo '```python'
echo '# Check for existing session'
echo 'if os.path.exists(f"{log_dir}/latest_session.json"):'
echo '    with open(...) as f:'
echo '        session_data = json.load(f)'
echo '        self.iteration = session_data["iteration"]'
echo '        self.conversation = session_data["conversation"]'
echo '        self.executions = session_data["executions"]'
echo '```'
echo ""

echo "## Current Behavior"
echo "------------------"
echo ""
echo "1. Agent starts:"
echo "   self.session_id = f"session_{datetime.now()...}"  # Always new!"
echo ""
echo "2. Agent ends:"
echo "   Session saved: /pentest/logs/session_session_20260112_164953.json"
echo ""
echo "3. Next run:"
echo "   Creates NEW session_id (doesn't load old one)"
echo ""

echo "## You're Absolutely Right!"
echo "-------------------------"
echo ""
echo "We HAVE session persistence (saving to JSON)"
echo "But we DON'T have session resume capability"
echo ""
echo "The agent saves 128K of session data but never reloads it"
echo "Each run starts fresh with a new session ID"
echo ""

echo "This is a missed opportunity for true resume capability!"
echo ""

