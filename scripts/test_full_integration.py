#!/usr/bin/env python3
"""
NeuroSploit SaaS v2 - Full Integration Test
Tests LLM -> Kali -> Target with complete logging
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime

# Add the open-interpreter path
sys.path.insert(0, '/opt/open-interpreter')

LOG_DIR = "/pentest/logs"
os.makedirs(LOG_DIR, exist_ok=True)

def log(msg, level="INFO"):
    timestamp = datetime.utcnow().isoformat()
    print(f"[{timestamp}] [{level}] {msg}")
    with open(f"{LOG_DIR}/integration_test.log", 'a') as f:
        f.write(f"[{timestamp}] [{level}] {msg}\n")

def test_llm_connection():
    """Test 1: Verify LLM Studio connection"""
    log("Testing LLM connection...")
    from llm_client import LLMClient
    
    client = LLMClient(LOG_DIR)
    try:
        response = client.chat([
            {"role": "system", "content": "Reply with only 'OK'"},
            {"role": "user", "content": "Test"}
        ], max_tokens=10)
        log(f"LLM response: {response}")
        return True, client.get_stats()
    except Exception as e:
        log(f"LLM connection failed: {e}", "ERROR")
        return False, str(e)

def test_command_execution():
    """Test 2: Verify command execution with capture"""
    log("Testing command execution...")
    
    test_commands = [
        ("nmap --version", "nmap"),
        ("nikto -Version", "nikto"),
        ("sqlmap --version", "sqlmap"),
    ]
    
    results = []
    for cmd, tool in test_commands:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            success = result.returncode == 0
            results.append({
                "tool": tool,
                "success": success,
                "output_len": len(result.stdout)
            })
            log(f"  {tool}: {'OK' if success else 'FAIL'}")
        except Exception as e:
            results.append({"tool": tool, "success": False, "error": str(e)})
            log(f"  {tool}: FAIL - {e}", "ERROR")
    
    return all(r["success"] for r in results), results

def test_target_connectivity(target):
    """Test 3: Verify target is reachable"""
    log(f"Testing target connectivity: {target}")
    
    try:
        result = subprocess.run(
            f"curl -s -o /dev/null -w '%{{http_code}}' {target}",
            shell=True, capture_output=True, text=True, timeout=10
        )
        status_code = result.stdout.strip()
        success = status_code in ["200", "302", "301"]
        log(f"  HTTP status: {status_code}")
        return success, status_code
    except Exception as e:
        log(f"  Target unreachable: {e}", "ERROR")
        return False, str(e)

def test_llm_pentest_integration(target):
    """Test 4: Full LLM-driven pentest with logging"""
    log(f"Running LLM pentest integration against {target}")
    
    from llm_client import PentestLLM
    
    llm = PentestLLM(target, LOG_DIR)
    llm.conversation = [
        {"role": "system", "content": """You are a penetration tester. Execute ONE command at a time.
Use FAST scans only (under 30 seconds). Available: nmap, nikto, curl, gobuster.
Analyze results and decide next step. Stop after 3 commands."""},
        {"role": "user", "content": f"Quick security assessment of {target}. Start with port scan."}
    ]
    
    executions = []
    for i in range(3):
        log(f"  Iteration {i+1}/3")
        
        try:
            response = llm.get_next_action()
            command = llm.extract_command(response)
            
            if not command:
                log(f"    No command extracted", "WARN")
                continue
            
            log(f"    Command: {command}")
            
            # Execute with timeout
            start = time.time()
            result = subprocess.run(
                command, shell=True, capture_output=True, 
                text=True, timeout=30, cwd="/pentest"
            )
            duration = int((time.time() - start) * 1000)
            
            execution = {
                "iteration": i + 1,
                "command": command,
                "exit_code": result.returncode,
                "stdout_len": len(result.stdout),
                "stderr_len": len(result.stderr),
                "duration_ms": duration
            }
            executions.append(execution)
            
            log(f"    Exit: {result.returncode}, Duration: {duration}ms")
            
            # Feed back to LLM
            llm.add_command_result(command, result.stdout[:1500] + result.stderr[:500], result.returncode)
            
            # Save execution log
            with open(f"{LOG_DIR}/executions.jsonl", 'a') as f:
                f.write(json.dumps(execution) + '\n')
                
        except subprocess.TimeoutExpired:
            log(f"    Timeout", "WARN")
            executions.append({"iteration": i+1, "timeout": True})
        except Exception as e:
            log(f"    Error: {e}", "ERROR")
            executions.append({"iteration": i+1, "error": str(e)})
    
    return len(executions) > 0, {
        "executions": executions,
        "llm_stats": llm.get_stats()
    }

def verify_logs():
    """Test 5: Verify all logs are captured"""
    log("Verifying log files...")
    
    log_files = [
        "llm_interactions.jsonl",
        "executions.jsonl",
        "integration_test.log"
    ]
    
    results = {}
    for lf in log_files:
        path = f"{LOG_DIR}/{lf}"
        exists = os.path.exists(path)
        size = os.path.getsize(path) if exists else 0
        lines = 0
        if exists:
            with open(path) as f:
                lines = sum(1 for _ in f)
        results[lf] = {"exists": exists, "size": size, "lines": lines}
        log(f"  {lf}: {'OK' if exists else 'MISSING'} ({size} bytes, {lines} lines)")
    
    return all(r["exists"] for r in results.values()), results

def main():
    """Run all integration tests"""
    print("=" * 60)
    print("NeuroSploit SaaS v2 - Full Integration Test")
    print("=" * 60)
    
    target = os.getenv("TEST_TARGET", "http://host.docker.internal:8888")
    log(f"Target: {target}")
    
    results = {}
    
    # Test 1: LLM Connection
    success, data = test_llm_connection()
    results["llm_connection"] = {"success": success, "data": data}
    
    # Test 2: Command Execution
    success, data = test_command_execution()
    results["command_execution"] = {"success": success, "data": data}
    
    # Test 3: Target Connectivity
    success, data = test_target_connectivity(target)
    results["target_connectivity"] = {"success": success, "data": data}
    
    # Test 4: LLM Pentest Integration
    if results["llm_connection"]["success"] and results["target_connectivity"]["success"]:
        success, data = test_llm_pentest_integration(target)
        results["llm_pentest"] = {"success": success, "data": data}
    else:
        results["llm_pentest"] = {"success": False, "data": "Skipped - prerequisites failed"}
    
    # Test 5: Verify Logs
    success, data = verify_logs()
    results["log_verification"] = {"success": success, "data": data}
    
    # Summary
    print("\n" + "=" * 60)
    print("INTEGRATION TEST RESULTS")
    print("=" * 60)
    
    all_passed = True
    for test_name, result in results.items():
        status = "PASS" if result["success"] else "FAIL"
        if not result["success"]:
            all_passed = False
        print(f"  {test_name}: {status}")
    
    print("=" * 60)
    print(f"OVERALL: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 60)
    
    # Save full results
    with open(f"{LOG_DIR}/integration_results.json", 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    log(f"Results saved to {LOG_DIR}/integration_results.json")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
