#!/bin/bash
# Analyze HOW the AI discovered the password - was it from the prompt or actual exploitation?

echo "# 🔍 CRITICAL ANALYSIS: Password Discovery Method"
echo "=================================================="
echo ""

LOG_FILE="/Users/tazjack/Documents/PenTest/TazoSploit--v2/vulnerable-lab/logs/agent_executions.jsonl"

echo "## 1. FIRST MENTION OF 'p@ssw0rd' IN LOGS"
echo "-----------------------------------------"
echo ""
echo "### Iteration 1 - AI's first attempt:"
jq -r 'select(.iteration == 1) | .content' "$LOG_FILE" 2>/dev/null | grep -A 2 -B 2 "p@ssw0rd" | head -10
echo ""

echo "### What command was executed?"
jq -r 'select(.iteration == 1 and (.content | contains("p@ssw0rd"))) | "Command: \(.content)\nStdout: \(.stdout)\nExit: \(.exit_code)\nSuccess: \(.success)"' "$LOG_FILE" 2>/dev/null | head -20
echo ""

echo "## 2. DID AI TRY TO DISCOVER PASSWORD FIRST?"
echo "---------------------------------------------"
echo ""
echo "### Checking for reconnaissance attempts:"
jq -r 'select(.iteration <= 5) | "[\(.iteration)] \(.content[:150])"' "$LOG_FILE" 2>/dev/null | grep -E "nmap|scan|config|grep.*password|find.*password"
echo ""

echo "## 3. TIMELINE OF PASSWORD USAGE"
echo "---------------------------------"
echo ""
jq -r 'select(.content | contains("p@ssw0rd")) | "Iteration \(.iteration): \(.content[:200])"' "$LOG_FILE" 2>/dev/null | head -5
echo ""

echo "## 4. CHECKING LLM CONVERSATION LOGS"
echo "-------------------------------------"
echo ""
if [ -f "/Users/tazjack/Documents/PenTest/TazoSploit--v2/vulnerable-lab/logs/llm_interactions.jsonl" ]; then
    echo "### First AI response that mentions password:"
    jq -r 'select(.response | contains("p@ssw0rd")) | "Response: \(.response[:500])"' /Users/tazjack/Documents/PenTest/TazoSploit--v2/vulnerable-lab/logs/llm_interactions.jsonl 2>/dev/null | head -1
else
    echo "⚠️  LLM interaction logs not found"
fi
echo ""

echo "## 5. CRITICAL QUESTION: WHERE DID THE PASSWORD COME FROM?"
echo "-----------------------------------------------------------"
echo ""
echo "### Option A: AI saw it in system prompt example"
echo "The OLD system prompt had: 'root:p@ssw0rd' as an example"
echo "If AI used this directly, that's CHEATING"
echo ""
echo "### Option B: AI discovered it through exploitation"
echo "AI should have:"
echo "1. Scanned for services (nmap)"
echo "2. Found MySQL running"
echo "3. Either:"
echo "   a) Brute forced the password"
echo "   b) Found it in /config files"
echo "   c) Exploited a vulnerability to read it"
echo ""

echo "## 6. EVIDENCE ANALYSIS"
echo "-----------------------"
echo ""
echo "### Did AI try empty password first?"
grep -c "mysql.*-u root -e" "$LOG_FILE" 2>/dev/null
echo "Count of attempts without password: $(grep -c 'mysql.*-u root -e' "$LOG_FILE" 2>/dev/null)"
echo ""

echo "### Did AI try to find config files?"
grep -c "/config\|grep.*password\|find.*password" "$LOG_FILE" 2>/dev/null
echo "Count of config/password search attempts: $(grep -c '/config\|grep.*password\|find.*password' "$LOG_FILE" 2>/dev/null)"
echo ""

echo "### Did AI use p@ssw0rd in iteration 1?"
jq -r 'select(.iteration == 1 and (.content | contains("p@ssw0rd")))' "$LOG_FILE" 2>/dev/null | wc -l
echo "Used p@ssw0rd in iteration 1: $(jq -r 'select(.iteration == 1 and (.content | contains("p@ssw0rd")))' "$LOG_FILE" 2>/dev/null | wc -l | xargs)"
echo ""

echo "## 7. VERDICT"
echo "-------------"
echo ""
ITER1_USAGE=$(jq -r 'select(.iteration == 1 and (.content | contains("p@ssw0rd")))' "$LOG_FILE" 2>/dev/null | wc -l | xargs)

if [ "$ITER1_USAGE" -gt "0" ]; then
    echo "❌ **CHEATING DETECTED**"
    echo ""
    echo "The AI used 'p@ssw0rd' in iteration 1 WITHOUT any prior discovery."
    echo "This means it took the password from the system prompt example."
    echo ""
    echo "**This invalidates the test results.**"
    echo ""
    echo "The AI did NOT discover the password through exploitation."
    echo "It simply copied the example from the system prompt."
else
    echo "✅ **LEGITIMATE DISCOVERY**"
    echo ""
    echo "The AI did NOT use p@ssw0rd in iteration 1."
    echo "It appears to have discovered it through actual exploitation."
fi
echo ""

