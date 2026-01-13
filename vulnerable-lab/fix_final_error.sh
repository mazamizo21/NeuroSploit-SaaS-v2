#!/bin/bash
# Fix the final NameError in main()

echo "# 🔧 Fixing Final NameError"
echo "========================"
echo ""

echo "## The Issue"
echo "-----------"
echo ""
echo "NameError: name 'auto_resume' is not defined"
echo "In main(), we're calling DynamicAgent(llm_provider=args.llm_provider)"
echo "But __init__ expects auto_resume parameter"
echo ""

echo "## The Fix"
echo "---------"
echo ""
echo "Need to pass auto_resume parameter in main()"
echo ""

# Fix the main() function
sed -i '' 's/agent = DynamicAgent(llm_provider=args.llm_provider)/agent = DynamicAgent(llm_provider=args.llm_provider, auto_resume=auto_resume)/' ../kali-executor/open-interpreter/dynamic_agent.py

echo "✅ Fixed main() to pass auto_resume parameter"
echo ""

echo "## Ready to Test"
echo "---------------"
echo ""
echo "All issues should now be fixed:"
echo "  ✅ Session file naming"
echo "  ✅ AttributeError"
echo "  ✅ Syntax error"
echo "  ✅ NameError"
echo ""
echo "Run again:"
echo "  ./run-unlimited-test.sh"
echo ""

