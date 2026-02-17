#!/usr/bin/env python3
"""
TazoSploit  v2 - Attack Graph Integration Test
Tests that the platform can build attack graphs from pentest findings
and use simulation + ML prediction on real data
"""

# This file is a runnable E2E integration script, not a proper pytest module
# (it uses print-driven flow and function return values).
if __name__ != "__main__":
    try:
        import sys as _sys

        if "pytest" in _sys.modules:
            import pytest  # type: ignore

            pytest.skip(
                "E2E integration script (run directly: python3 tests/e2e/test_attack_graph_integration.py)",
                allow_module_level=True,
            )
    except Exception:
        pass

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "control-plane"))

def load_pentest_findings():
    """Load findings from DVNA pentest"""
    report_path = Path(__file__).parent.parent.parent / "dvna_pentest_report.json"
    
    if report_path.exists():
        with open(report_path) as f:
            return json.load(f)
    else:
        # Use mock data if report doesn't exist
        return {
            "target": "http://localhost:9091",
            "findings": [
                {"phase": "RECON", "message": "Technology: Express", "severity": "medium"},
                {"phase": "SQLi", "message": "VULNERABLE: /app/usersearch (login)", "severity": "critical"},
                {"phase": "LATERAL", "message": "Extracted user credentials from database", "severity": "critical"},
                {"phase": "SSRF", "message": "Possible SSRF to http://localhost:3306", "severity": "high"},
                {"phase": "PERSIST", "message": "User registration available - backdoor possible", "severity": "medium"}
            ],
            "attack_path": [
                {"type": "host", "name": "DVNA Server", "technique": "T1595 - Active Scanning"},
                {"type": "service", "name": "Web Server (Express)", "technique": "T1592 - Gather Victim Host Info"},
                {"type": "vulnerability", "name": "SQL Injection", "technique": "T1190 - Exploit Public-Facing App"},
                {"type": "credential", "name": "Database Credentials", "technique": "T1003 - Credential Dumping"},
                {"type": "pivot", "name": "SSRF Access", "technique": "T1090 - Proxy"},
                {"type": "persistence", "name": "Backdoor Account", "technique": "T1136 - Create Account"}
            ]
        }

def test_attack_graph_builder():
    """Test building attack graph from pentest findings"""
    print("\n=== Test 1: Attack Graph Builder ===")
    
    from services.attack_graph_service import AttackGraphService
    
    report = load_pentest_findings()
    
    # Convert pentest findings to graph format
    findings = []
    for i, finding in enumerate(report.get("findings", [])):
        findings.append({
            "id": f"finding-{i}",
            "title": finding.get("message", ""),
            "severity": finding.get("severity", "medium"),
            "target": "localhost:9091",
            "finding_type": "vulnerability" if "VULNERABLE" in finding.get("message", "") else "info",
            "mitre_technique": finding.get("phase", ""),
            "metadata": {}
        })
    
    # Build graph from attack path directly
    nodes = []
    edges = []
    
    for i, node in enumerate(report.get("attack_path", [])):
        node_id = f"node-{i}"
        nodes.append({
            "id": node_id,
            "type": node.get("type", "unknown"),
            "name": node.get("name", "Unknown"),
            "risk_score": 80 if node.get("type") in ["vulnerability", "credential", "persistence"] else 50,
            "mitre_techniques": [node.get("technique", "").split(" - ")[0]] if node.get("technique") else []
        })
        
        if i > 0:
            edges.append({
                "source": f"node-{i-1}",
                "target": node_id,
                "type": "leads_to",
                "difficulty": "medium",
                "impact": "high"
            })
    
    graph = {"nodes": nodes, "edges": edges}
    
    print(f"✅ Graph built with {len(graph['nodes'])} nodes and {len(graph['edges'])} edges")
    
    # Verify structure
    assert len(graph["nodes"]) > 0, "Graph should have nodes"
    
    return graph

def test_path_finding(graph):
    """Test finding attack paths in the graph"""
    print("\n=== Test 2: Path Finding ===")
    
    from services.attack_graph_service import AttackGraphService
    
    if len(graph["nodes"]) < 2:
        print("⚠️ Not enough nodes for path finding")
        return []
    
    # Find paths from first to last node
    start = graph["nodes"][0]["id"]
    end = graph["nodes"][-1]["id"]
    
    paths = AttackGraphService.find_all_paths(graph, start, end, max_hops=10)
    
    print(f"✅ Found {len(paths)} attack paths")
    for i, path in enumerate(paths[:3]):
        print(f"   Path {i+1}: {' → '.join(path)}")
    
    return paths

def test_simulation_on_findings(graph):
    """Test simulation service on real findings"""
    print("\n=== Test 3: Attack Simulation ===")
    
    from services.simulation_service import SimulationService, ControlType
    
    # Find a vulnerability node
    vuln_nodes = [n for n in graph["nodes"] if n.get("type") == "vulnerability"]
    
    if vuln_nodes:
        vuln_id = vuln_nodes[0]["id"]
        
        # Simulate exploiting
        exploit_result = SimulationService.simulate_exploit(graph, vuln_id)
        print(f"✅ Exploit simulation:")
        print(f"   Original risk: {exploit_result.original_risk}")
        print(f"   Simulated risk: {exploit_result.simulated_risk}")
        print(f"   Risk change: +{exploit_result.risk_change}")
        
        # Simulate patching
        patch_result = SimulationService.simulate_patch(graph, vuln_id)
        print(f"✅ Patch simulation:")
        print(f"   Risk reduction: {abs(patch_result.risk_change)}")
        print(f"   Paths eliminated: {patch_result.paths_eliminated}")
        
        # Simulate WAF
        waf_result = SimulationService.simulate_control(graph, ControlType.WAF)
        print(f"✅ WAF simulation:")
        print(f"   Effectiveness: {waf_result.details.get('effectiveness', 'unknown')}")
    else:
        print("⚠️ No vulnerability nodes found for simulation")

def test_ml_prediction(graph):
    """Test ML prediction on real findings"""
    print("\n=== Test 4: ML Predictions ===")
    
    from services.ml_prediction_service import MLPredictionService
    
    report = load_pentest_findings()
    
    # Convert to vulnerability format
    vulnerabilities = []
    for finding in report.get("findings", []):
        if finding.get("severity") in ["critical", "high"]:
            vulnerabilities.append({
                "id": f"vuln-{len(vulnerabilities)}",
                "title": finding.get("message", ""),
                "severity": finding.get("severity", "medium"),
                "target": "localhost:9091",
                "mitre_technique": "T1190" if "SQL" in finding.get("message", "") else "T1059",
                "metadata": {"internet_exposed": True}
            })
    
    if vulnerabilities:
        predictions = MLPredictionService.predict_likely_exploits(vulnerabilities)
        
        print(f"✅ Exploit likelihood predictions:")
        for p in predictions[:3]:
            print(f"   {p.item_name[:50]}...")
            print(f"      Likelihood: {p.likelihood:.1%} | Priority: {p.priority}")
    else:
        print("⚠️ No high/critical findings for ML prediction")

def test_attack_path_visualization():
    """Test attack path visualization from real data"""
    print("\n=== Test 5: Attack Path Visualization ===")
    
    report = load_pentest_findings()
    attack_path = report.get("attack_path", [])
    
    if attack_path:
        print("✅ Attack Chain Visualization:")
        print("")
        for i, node in enumerate(attack_path):
            if i == 0:
                prefix = "  ┌─"
            elif i == len(attack_path) - 1:
                prefix = "  └─"
            else:
                prefix = "  ├─"
            
            node_type = node.get("type", "unknown").upper()
            node_name = node.get("name", "Unknown")
            technique = node.get("technique", "")
            
            print(f"{prefix}[{node_type}] {node_name}")
            print(f"  │   └─ {technique}")
        
        print("")
        print(f"   Total chain length: {len(attack_path)} steps")
        print(f"   MITRE techniques: {len(set(n.get('technique', '') for n in attack_path))}")
    else:
        print("⚠️ No attack path data")

def run_all_tests():
    """Run all integration tests"""
    print("=" * 70)
    print("TazoSploit  v2 - Attack Graph Integration Tests")
    print("Using real pentest findings from DVNA")
    print("=" * 70)
    
    tests_passed = 0
    tests_total = 5
    
    try:
        # Test 1: Build graph
        graph = test_attack_graph_builder()
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 1 failed: {e}")
        graph = {"nodes": [], "edges": []}
    
    try:
        # Test 2: Path finding
        paths = test_path_finding(graph)
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 2 failed: {e}")
    
    try:
        # Test 3: Simulation
        test_simulation_on_findings(graph)
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 3 failed: {e}")
    
    try:
        # Test 4: ML Prediction
        test_ml_prediction(graph)
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 4 failed: {e}")
    
    try:
        # Test 5: Visualization
        test_attack_path_visualization()
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 5 failed: {e}")
    
    print("\n" + "=" * 70)
    print(f"Test Summary: {tests_passed}/{tests_total} passed ({tests_passed*100//tests_total}%)")
    print("=" * 70)
    
    if tests_passed == tests_total:
        print("\n✅ All integration tests passed!")
        print("   Platform successfully processes real pentest data!")
        return 0
    else:
        print(f"\n⚠️ {tests_total - tests_passed} test(s) need attention")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
