#!/bin/bash
# Restore original dynamic_agent.py and test Claude

echo "# 🔄 Restoring Original Agent"
echo "==========================="
echo ""

echo "## Auto-Resume Implementation Failed"
echo "---------------------------------"
echo ""
echo "The auto-resume implementation has too many issues"
echo "Let's restore the original and test Claude normally"
echo ""

# Restore from git if available
cd ../kali-executor/open-interpreter
git checkout dynamic_agent.py 2>/dev/null && echo "✅ Restored from git" || echo "❌ Not a git repo"
cd - > /dev/null

echo ""
echo "## Testing Claude with Original Code"
echo "-----------------------------------"
echo ""
echo "Claude should work with:"
echo "  ✅ Updated system prompt (tool installation)"
echo "  ✅ Original agent code"
echo "  ✅ No auto-resume complications"
echo ""

echo "## Ready to Test"
echo "---------------"
echo ""
echo "Run:"
echo "  ./run-unlimited-test.sh"
echo ""

