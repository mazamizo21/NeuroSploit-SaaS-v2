#!/bin/bash
# Check and fix the main function

echo "# 🔍 Checking Main Function"
echo "========================"
echo ""

echo "## Current main() around line 667"
echo "--------------------------------"
sed -n '665,670p' ../kali-executor/open-interpreter/dynamic_agent.py
echo ""

echo "## The Issue"
echo "-----------"
echo ""
echo "auto_resume is defined in the scope but not accessible where we're using it"
echo "Need to check the scope properly"
echo ""

echo "## Checking full context"
echo "---------------------"
sed -n '660,675p' ../kali-executor/open-interpreter/dynamic_agent.py
echo ""

echo "## The Fix"
echo "---------"
echo ""
echo "The auto_resume variable is defined but scope issue"
echo "Let's fix this properly"
echo ""

# Fix the scope issue
sed -i '' 's/# Check for auto-resume mode/# Check for auto-resume mode\
    auto_resume = not args.resume  # Auto-resume unless explicit session provided/' ../kali-executor/open-interpreter/dynamic_agent.py

echo "✅ Fixed auto_resume scope"
echo ""

echo "## Ready to Test"
echo "---------------"
echo ""
echo "Run again:"
echo "  ./run-unlimited-test.sh"
echo ""

