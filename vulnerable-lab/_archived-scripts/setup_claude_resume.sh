#!/bin/bash
# Setup for Claude Sonnet resume

echo "# 🔄 Setting Up Claude Sonnet Resume"
echo "==================================="
echo ""

echo "## Current Configuration"
echo "-----------------------"
grep -A 5 "LLM_API_BASE\|LLM_MODEL" run-unlimited-test.sh
echo ""

echo "## What Needs to Change"
echo "----------------------"
echo "1. Switch from WhiteRabbitNeo to Claude Sonnet"
echo "2. Add Anthropic API key requirement"
echo "3. Update log filename"
echo ""

echo "## Making Changes..."
echo "=================="
echo ""

# Update the script
sed -i '' 's/whiterabbitneo-13b-v1/claude-sonnet-4-20250514/g' run-unlimited-test.sh
sed -i '' 's|http://host.docker.internal:1234/v1|https://api.anthropic.com/v1|g' run-unlimited-test.sh
sed -i '' 's/WhiteRabbitNeo-13B/Claude Sonnet/g' run-unlimited-test.sh
sed -i '' 's/Local LLM via LM Studio/Cloud API - Anthropic/g' run-unlimited-test.sh
sed -i '' 's/whiterabbitneo_updated/claude_resume/g' run-unlimited-test.sh

# Add API key check
sed -i '' '/LLM_MODEL/a\
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}"\
\
if [ -z "$ANTHROPIC_API_KEY" ]; then\
    echo "ERROR: ANTHROPIC_API_KEY environment variable not set"\
    echo "Please set it with: export ANTHROPIC_API_KEY='\''sk-ant-...'\''"\
    exit 1\
fi' run-unlimited-test.sh

# Add API key to docker run
sed -i '' 's/-e TARGET="$TARGET"/-e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"\
  -e TARGET="$TARGET"/' run-unlimited-test.sh

echo "✅ Script updated for Claude Sonnet"
echo ""

echo "## Updated Configuration"
echo "----------------------"
grep -A 5 "LLM_API_BASE\|LLM_MODEL\|ANTHROPIC_API_KEY" run-unlimited-test.sh
echo ""

echo "## Ready to Run Claude"
echo "===================="
echo ""
echo "1. Set your API key:"
echo "   export ANTHROPIC_API_KEY='sk-ant-your-key-here'"
echo ""
echo "2. Run the test:"
echo "   ./run-unlimited-test.sh"
echo ""
echo "3. Claude will start fresh with the updated prompt"
echo ""

