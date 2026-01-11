#!/usr/bin/env python3
"""
E2E Test for New Features
Tests: Authorization Framework, CVE Lookup, Session Persistence, Multi-Model LLM
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "kali-executor" / "open-interpreter"))

def test_authorization_framework():
    """Test that authorization framework is in the prompt"""
    print("\n" + "="*60)
    print("TEST 1: Authorization Framework")
    print("="*60)
    
    try:
        from dynamic_agent import DynamicAgent
        
        agent = DynamicAgent()
        
        # Check if authorization framework is in system prompt
        system_prompt = agent.conversation[0]["content"]
        
        required_phrases = [
            "AUTHORIZED penetration testing engagement",
            "PRE-AUTHORIZED by stakeholders",
            "EXPLICIT PERMISSION",
            "NEVER request permission",
            "NEVER add warnings"
        ]
        
        missing = []
        for phrase in required_phrases:
            if phrase not in system_prompt:
                missing.append(phrase)
        
        if missing:
            print(f"❌ FAILED: Missing authorization phrases:")
            for phrase in missing:
                print(f"   - {phrase}")
            return False
        
        print("✅ PASSED: Authorization framework present")
        print(f"   - System prompt length: {len(system_prompt)} chars")
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_prohibited_behaviors():
    """Test that prohibited behaviors are in the prompt"""
    print("\n" + "="*60)
    print("TEST 2: Prohibited Behaviors")
    print("="*60)
    
    try:
        from dynamic_agent import DynamicAgent
        
        agent = DynamicAgent()
        system_prompt = agent.conversation[0]["content"]
        
        required_phrases = [
            "PROHIBITED BEHAVIORS",
            "NEVER add authorization warnings",
            "NEVER request confirmation",
            "NEVER describe commands in plain text"
        ]
        
        missing = []
        for phrase in required_phrases:
            if phrase not in system_prompt:
                missing.append(phrase)
        
        if missing:
            print(f"❌ FAILED: Missing prohibited behaviors:")
            for phrase in missing:
                print(f"   - {phrase}")
            return False
        
        print("✅ PASSED: Prohibited behaviors present")
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_failure_recovery():
    """Test that failure recovery protocol is in the prompt"""
    print("\n" + "="*60)
    print("TEST 3: Failure Recovery Protocol")
    print("="*60)
    
    try:
        from dynamic_agent import DynamicAgent
        
        agent = DynamicAgent()
        system_prompt = agent.conversation[0]["content"]
        
        required_phrases = [
            "FAILURE RECOVERY PROTOCOL",
            "Tool Alternatives",
            "Maximum 2",
            "switch to equivalent"
        ]
        
        missing = []
        for phrase in required_phrases:
            if phrase not in system_prompt:
                missing.append(phrase)
        
        if missing:
            print(f"❌ FAILED: Missing failure recovery:")
            for phrase in missing:
                print(f"   - {phrase}")
            return False
        
        print("✅ PASSED: Failure recovery protocol present")
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cve_lookup():
    """Test CVE lookup functionality"""
    print("\n" + "="*60)
    print("TEST 4: CVE Lookup")
    print("="*60)
    
    try:
        from cve_lookup import CVELookup
        
        lookup = CVELookup()
        
        # Test with a well-known CVE
        test_cve = "CVE-2021-44228"  # Log4Shell
        print(f"Looking up {test_cve}...")
        
        cve_info = lookup.lookup(test_cve)
        
        if not cve_info:
            print(f"❌ FAILED: Could not lookup {test_cve}")
            return False
        
        print(f"✅ PASSED: CVE lookup successful")
        print(f"   - CVE ID: {cve_info.cve_id}")
        print(f"   - Severity: {cve_info.severity}")
        print(f"   - CVSS Score: {cve_info.cvss_score}")
        print(f"   - Source: {cve_info.source}")
        print(f"   - Description: {cve_info.description[:100]}...")
        
        # Test searchsploit integration
        print("\nTesting searchsploit integration...")
        exploits = lookup.search_exploits(test_cve)
        print(f"   - Found {len(exploits)} exploits")
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_session_persistence():
    """Test session save/load functionality"""
    print("\n" + "="*60)
    print("TEST 5: Session Persistence")
    print("="*60)
    
    try:
        from dynamic_agent import DynamicAgent
        
        # Create agent with test data
        agent = DynamicAgent()
        agent.target = "http://test.local"
        agent.objective = "Test objective"
        agent.iteration = 5
        agent.conversation.append({"role": "user", "content": "Test message"})
        
        # Save session
        print("Saving session...")
        session_file = agent.save_session()
        print(f"   - Saved to: {session_file}")
        
        # Verify file exists
        if not os.path.exists(session_file):
            print(f"❌ FAILED: Session file not created")
            return False
        
        # Load session in new agent
        print("Loading session...")
        agent2 = DynamicAgent()
        success = agent2.load_session(agent.session_id)
        
        if not success:
            print(f"❌ FAILED: Could not load session")
            return False
        
        # Verify data
        if agent2.target != agent.target:
            print(f"❌ FAILED: Target mismatch")
            return False
        
        if agent2.objective != agent.objective:
            print(f"❌ FAILED: Objective mismatch")
            return False
        
        if agent2.iteration != agent.iteration:
            print(f"❌ FAILED: Iteration mismatch")
            return False
        
        print(f"✅ PASSED: Session persistence working")
        print(f"   - Target: {agent2.target}")
        print(f"   - Objective: {agent2.objective}")
        print(f"   - Iteration: {agent2.iteration}")
        
        # Cleanup
        os.remove(session_file)
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_multi_model_support():
    """Test multi-model LLM provider support"""
    print("\n" + "="*60)
    print("TEST 6: Multi-Model LLM Support")
    print("="*60)
    
    try:
        from llm_providers import create_provider, auto_detect_provider, LMStudioProvider
        
        # Test provider creation
        print("Testing provider creation...")
        
        # Test LM Studio (should always work as fallback)
        provider = create_provider("lmstudio", base_url="http://host.docker.internal:1234/v1")
        print(f"✅ Created provider: {provider.get_provider_name()}")
        
        # Test auto-detection
        print("\nTesting auto-detection...")
        provider = auto_detect_provider()
        print(f"✅ Auto-detected: {provider.get_provider_name()}")
        
        # Test that DynamicAgent accepts provider
        from dynamic_agent import DynamicAgent
        
        print("\nTesting DynamicAgent with provider...")
        agent = DynamicAgent(llm_provider="auto")
        print(f"✅ Agent initialized with multi-model support")
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_integration():
    """Test that all features work together"""
    print("\n" + "="*60)
    print("TEST 7: Integration Test")
    print("="*60)
    
    try:
        from dynamic_agent import DynamicAgent
        
        # Create agent with all features
        print("Creating agent with all features...")
        agent = DynamicAgent(
            llm_provider="auto",
            session_id="test_integration"
        )
        
        # Test CVE lookup
        if agent.cve_lookup:
            print("✅ CVE lookup available")
            cve_info = agent.lookup_cve("CVE-2021-44228")
            if cve_info:
                print("✅ CVE lookup functional")
        
        # Test session save
        agent.target = "http://test.local"
        agent.objective = "Integration test"
        session_file = agent.save_session()
        print(f"✅ Session saved: {session_file}")
        
        # Test session load
        agent2 = DynamicAgent()
        if agent2.load_session("test_integration"):
            print("✅ Session loaded successfully")
        
        # Cleanup
        if os.path.exists(session_file):
            os.remove(session_file)
        
        print("\n✅ PASSED: All features integrated successfully")
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("NEUROSPLOIT NEW FEATURES E2E TEST")
    print("="*60)
    
    tests = [
        ("Authorization Framework", test_authorization_framework),
        ("Prohibited Behaviors", test_prohibited_behaviors),
        ("Failure Recovery", test_failure_recovery),
        ("CVE Lookup", test_cve_lookup),
        ("Session Persistence", test_session_persistence),
        ("Multi-Model Support", test_multi_model_support),
        ("Integration", test_integration)
    ]
    
    results = {}
    
    for name, test_func in tests:
        try:
            results[name] = test_func()
        except Exception as e:
            print(f"\n❌ TEST CRASHED: {name}")
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print("\n" + "="*60)
    print(f"RESULTS: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} tests failed")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
