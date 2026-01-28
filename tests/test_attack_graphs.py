#!/usr/bin/env python3
"""
TazoSploit  v2 - Attack Graphs Integration Tests
Tests for Phase 2 attack path visualization features
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "control-plane"))

from services.attack_graph_service import AttackGraphService

def test_graph_builder():
    """Test building attack graph from findings"""
    print("\n=== Test 1: Graph Builder ===")
    
    # Sample findings
    findings = [
        {
            "finding_type": "open_port",
            "target": "192.168.1.10",
            "severity": "info",
            "title": "SSH Service",
            "description": "SSH service detected on port 22",
            "mitre_technique": "T1046",
            "metadata": {"port": 22, "protocol": "tcp"}
        },
        {
            "finding_type": "vulnerability",
            "target": "192.168.1.10",
            "severity": "high",
            "title": "OpenSSH CVE-2023-38408",
            "description": "Remote code execution vulnerability",
            "mitre_technique": "T1190",
            "cve_id": "CVE-2023-38408",
            "metadata": {"cvss_score": 8.1}
        },
        {
            "finding_type": "exploit",
            "target": "192.168.1.10",
            "severity": "critical",
            "title": "Successful RCE",
            "description": "Successfully exploited SSH vulnerability",
            "mitre_technique": "T1059",
            "metadata": {"exploit_type": "remote"}
        }
    ]
    
    targets = ["192.168.1.10"]
    
    # Build graph
    from uuid import uuid4
    job_id = uuid4()
    graph = AttackGraphService.build_graph_from_findings(job_id, findings, targets)
    
    print(f"✅ Graph built successfully")
    print(f"   Nodes: {graph['node_count']}")
    print(f"   Edges: {graph['edge_count']}")
    
    assert graph['node_count'] > 0, "Should have nodes"
    assert graph['edge_count'] > 0, "Should have edges"
    
    # Verify node types
    node_types = {n['type'] for n in graph['nodes']}
    print(f"   Node types: {node_types}")
    
    return graph

def test_path_finding():
    """Test finding attack paths"""
    print("\n=== Test 2: Path Finding ===")
    
    # Create a simple graph
    graph = {
        "nodes": [
            {"id": "node-1", "type": "host", "name": "Entry Point", "risk_score": 50},
            {"id": "node-2", "type": "service", "name": "Web Server", "risk_score": 60},
            {"id": "node-3", "type": "vulnerability", "name": "SQL Injection", "risk_score": 80},
            {"id": "node-4", "type": "exploit", "name": "Database Access", "risk_score": 90}
        ],
        "edges": [
            {"source": "node-1", "target": "node-2", "type": "hosts", "impact": "low"},
            {"source": "node-2", "target": "node-3", "type": "has_vulnerability", "impact": "high"},
            {"source": "node-3", "target": "node-4", "type": "exploits", "impact": "critical"}
        ]
    }
    
    # Find paths
    paths = AttackGraphService.find_all_paths(graph, "node-1", "node-4", max_hops=10)
    
    print(f"✅ Found {len(paths)} paths")
    for i, path in enumerate(paths, 1):
        print(f"   Path {i}: {' → '.join(path)}")
    
    assert len(paths) > 0, "Should find at least one path"
    assert "node-1" in paths[0], "Path should start with node-1"
    assert "node-4" in paths[0], "Path should end with node-4"
    
    return paths

def test_risk_calculation():
    """Test path risk scoring"""
    print("\n=== Test 3: Risk Calculation ===")
    
    graph = {
        "nodes": [
            {"id": "node-1", "type": "host", "name": "Entry", "risk_score": 30},
            {"id": "node-2", "type": "vulnerability", "name": "Vuln", "risk_score": 80},
            {"id": "node-3", "type": "exploit", "name": "Exploit", "risk_score": 90}
        ],
        "edges": [
            {"source": "node-1", "target": "node-2", "type": "has_vulnerability", "impact": "high"},
            {"source": "node-2", "target": "node-3", "type": "exploits", "impact": "critical"}
        ]
    }
    
    path = ["node-1", "node-2", "node-3"]
    risk_score = AttackGraphService.calculate_path_risk(graph, path)
    
    print(f"✅ Risk score calculated: {risk_score}/100")
    print(f"   Path length: {len(path)} hops")
    print(f"   Risk level: {'Critical' if risk_score >= 75 else 'High' if risk_score >= 50 else 'Medium'}")
    
    assert 0 <= risk_score <= 100, "Risk score should be 0-100"
    assert risk_score > 50, "High-risk path should have score > 50"
    
    return risk_score

def test_critical_paths():
    """Test identifying critical paths"""
    print("\n=== Test 4: Critical Path Identification ===")
    
    graph = {
        "nodes": [
            {"id": "node-1", "type": "host", "name": "192.168.1.10", "risk_score": 40, "metadata": {"target": "192.168.1.10"}},
            {"id": "node-2", "type": "service", "name": "Database", "risk_score": 60, "metadata": {"target": "192.168.1.50"}},
            {"id": "node-3", "type": "exploit", "name": "Admin Access", "risk_score": 90, "metadata": {"target": "192.168.1.50"}}
        ],
        "edges": [
            {"source": "node-1", "target": "node-2", "type": "accesses", "impact": "medium"},
            {"source": "node-2", "target": "node-3", "type": "exploits", "impact": "critical"}
        ]
    }
    
    critical_assets = [
        {
            "name": "Production Database",
            "asset_type": "database",
            "criticality": "critical",
            "identifiers": {"ip": "192.168.1.50"}
        }
    ]
    
    critical_paths = AttackGraphService.identify_critical_paths(graph, critical_assets, max_paths=5)
    
    print(f"✅ Found {len(critical_paths)} critical paths")
    for i, path in enumerate(critical_paths, 1):
        print(f"   Path {i}: Risk {path['risk_score']}/100, Length {path['length']} hops")
    
    if critical_paths:
        assert critical_paths[0]['is_critical'], "Should be marked as critical"
    
    return critical_paths

def test_recommendations():
    """Test generating recommendations"""
    print("\n=== Test 5: Recommendations Generation ===")
    
    graph = {
        "nodes": [
            {"id": "node-1", "type": "host", "name": "Entry", "risk_score": 40},
            {"id": "node-2", "type": "vulnerability", "name": "Critical Vuln", "risk_score": 85},
            {"id": "node-3", "type": "exploit", "name": "Exploit", "risk_score": 90}
        ],
        "edges": [
            {"source": "node-1", "target": "node-2", "type": "has_vulnerability", "impact": "high"},
            {"source": "node-2", "target": "node-3", "type": "exploits", "impact": "critical"}
        ]
    }
    
    paths = [
        {
            "path_nodes": ["node-1", "node-2", "node-3"],
            "risk_score": 85,
            "length": 3,
            "start_node": "node-1",
            "end_node": "node-3"
        }
    ]
    
    recommendations = AttackGraphService.generate_recommendations(paths, graph)
    
    print(f"✅ Generated {len(recommendations)} recommendations:")
    for i, rec in enumerate(recommendations, 1):
        print(f"   {i}. {rec}")
    
    assert len(recommendations) > 0, "Should generate recommendations"
    
    return recommendations

def run_all_tests():
    """Run all attack graph tests"""
    print("=" * 80)
    print("TazoSploit  v2 - Attack Graphs Integration Tests")
    print("=" * 80)
    
    tests_run = 0
    tests_passed = 0
    
    try:
        test_graph_builder()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 1 failed: {e}")
        tests_run += 1
    
    try:
        test_path_finding()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 2 failed: {e}")
        tests_run += 1
    
    try:
        test_risk_calculation()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 3 failed: {e}")
        tests_run += 1
    
    try:
        test_critical_paths()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 4 failed: {e}")
        tests_run += 1
    
    try:
        test_recommendations()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 5 failed: {e}")
        tests_run += 1
    
    print("\n" + "=" * 80)
    print(f"Test Summary: {tests_passed}/{tests_run} passed ({tests_passed*100//tests_run}%)")
    print("=" * 80)
    
    if tests_passed == tests_run:
        print("\n✅ All Phase 2 tests passed!")
        return 0
    else:
        print(f"\n⚠️  {tests_run - tests_passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
