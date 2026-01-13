#!/bin/bash
# Debug the auto-resume issue

echo "# 🔍 Auto-Resume Debug Analysis"
echo "==============================="
echo ""

echo "## Issue 1: Session File Not Found"
echo "--------------------------------"
echo ""
echo "Expected: /pentest/logs/session_20260112_164953.json"
echo "Actual: File not found in container"
echo ""
echo "Checking host logs:"
ls -la logs/session_*.json 2>/dev/null || echo "No session files on host"
echo ""

echo "## Issue 2: 404 Error from Anthropic"
echo "----------------------------------"
echo ""
echo "Error: 404 Not Found for https://api.anthropic.com/v1/messages"
echo "This suggests:"
echo "  - Wrong API endpoint"
echo "  - Invalid model name"
echo "  - API key issue"
echo ""

echo "## Issue 3: AttributeError"
echo "-------------------------"
echo ""
echo "Error: 'AnthropicProvider' object has no attribute 'get_stats'"
echo "The multi-model provider doesn't have get_stats() method"
echo ""

echo "## Root Causes"
echo "-------------"
echo ""
echo "1. Session file path mismatch"
echo "2. LLM provider configuration issue"
echo "3. Multi-model provider missing methods"
echo ""

echo "## Fixes Needed"
echo "-------------"
echo ""
echo "1. Fix session file mounting/volume mapping"
echo "2. Fix LLM provider auto-detection"
echo "3. Add get_stats() to AnthropicProvider"
echo ""

echo "## Quick Test: Check Session Files"
echo "--------------------------------"
if [ -f "logs/session_session_20260112_164953.json" ]; then
    echo "✅ Session file exists on host"
    echo "Size: $(du -h logs/session_session_20260112_164953.json | cut -f1)"
    echo "Should be mounted at: /pentest/logs/session_session_20260112_164953.json"
else
    echo "❌ No session file found"
fi
echo ""

echo "## Recommendation"
echo "----------------"
echo ""
echo "The auto-resume code is working but:"
echo "1. Session files not accessible in container"
echo "2. LLM provider issues preventing execution"
echo "3. Need to fix multi-model provider compatibility"
echo ""

