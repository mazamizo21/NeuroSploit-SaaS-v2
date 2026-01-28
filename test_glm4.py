#!/usr/bin/env python3
"""
Test GLM 4.7 model via LM Studio
"""

import os
import sys
import json

# Add the kali-executor path to import our LLM client
sys.path.insert(0, '/Users/tazjack/Documents/PenTest/TazoSploit--v2/kali-executor/open-interpreter')

from llm_client import LLMClient

def test_glm4():
    """Test GLM 4.7 model connection and basic functionality"""
    
    # Configure for LM Studio with GLM 4.7
    os.environ["LLM_API_BASE"] = "http://localhost:1234/v1"
    os.environ["LLM_MODEL"] = "glm-4-9b-chat"  # Adjust if your model name is different
    
    print("=" * 60)
    print("Testing GLM 4.7 via LM Studio")
    print("=" * 60)
    print(f"API Base: {os.environ['LLM_API_BASE']}")
    print(f"Model: {os.environ['LLM_MODEL']}")
    print()
    
    # Initialize client
    client = LLMClient(log_dir="./logs")
    
    # Test 1: Simple math
    print("Test 1: Simple reasoning")
    print("-" * 60)
    response = client.chat([
        {"role": "system", "content": "You are a helpful AI assistant."},
        {"role": "user", "content": "What is 2+2? Reply with just the number."}
    ], max_tokens=50, temperature=0.1)
    print(f"Response: {response}")
    print()
    
    # Test 2: Security knowledge
    print("Test 2: Security knowledge")
    print("-" * 60)
    response = client.chat([
        {"role": "system", "content": "You are a cybersecurity expert."},
        {"role": "user", "content": "What is the default port for SSH? Reply with just the port number."}
    ], max_tokens=50, temperature=0.1)
    print(f"Response: {response}")
    print()
    
    # Test 3: Command generation
    print("Test 3: Pentest command generation")
    print("-" * 60)
    response = client.chat([
        {"role": "system", "content": "You are a penetration testing expert."},
        {"role": "user", "content": "Generate an nmap command to scan 192.168.1.1 for open ports. Reply with just the command in a bash code block."}
    ], max_tokens=200, temperature=0.3)
    print(f"Response: {response}")
    print()
    
    # Test 4: Multi-turn conversation
    print("Test 4: Multi-turn conversation")
    print("-" * 60)
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "I'm testing a web application."},
        {"role": "assistant", "content": "Great! What kind of testing are you planning to do?"},
        {"role": "user", "content": "SQL injection testing. What tool should I use?"}
    ]
    response = client.chat(messages, max_tokens=200, temperature=0.5)
    print(f"Response: {response}")
    print()
    
    # Show stats
    print("=" * 60)
    print("Statistics")
    print("=" * 60)
    stats = client.get_stats()
    print(json.dumps(stats, indent=2))
    print()
    print("✓ All tests completed successfully!")
    print(f"✓ Logs saved to: ./logs/llm_interactions.jsonl")

if __name__ == "__main__":
    try:
        test_glm4()
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
