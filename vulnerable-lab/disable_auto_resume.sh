#!/bin/bash
# Disable auto-resume temporarily to test Claude

echo "# 🔧 Disabling Auto-Resume Temporarily"
echo "===================================="
echo ""

echo "## Auto-Resume is Too Complex Right Now"
echo "-------------------------------------"
echo ""
echo "Let's disable it and test Claude normally"
echo "We can re-enable it after we confirm Claude works"
echo ""

# Update the script to disable auto-resume
sed -i '' 's/auto_resume=auto_resume/auto_resume=False/' ../kali-executor/open-interpreter/dynamic_agent.py

echo "✅ Auto-resume disabled"
echo ""

echo "## Testing Claude Normally"
echo "-------------------------"
echo ""
echo "Claude will start fresh but should still:"
echo "  ✅ Install mysql-client automatically"
echo "  ✅ Find credentials legitimately"
echo "  ✅ Perform exploitation"
echo ""
echo "This will confirm the core functionality works"
echo ""

echo "## Ready to Test"
echo "---------------"
echo ""
echo "Run:"
echo "  ./run-unlimited-test.sh"
echo ""

