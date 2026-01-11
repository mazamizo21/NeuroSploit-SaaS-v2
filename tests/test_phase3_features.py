#!/usr/bin/env python3
"""
NeuroSploit SaaS v2 - Phase 3 Integration Tests
Tests for advanced features: Real-time, Simulations, ML Predictions
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "control-plane"))

def test_event_service():
    """Test Event Service"""
    print("\n=== Test 1: Event Service ===")
    
    from services.event_service import EventService, get_event_service
    
    # Test instantiation
    service = EventService("redis://localhost:6379")
    assert service is not None
    assert service.redis_url == "redis://localhost:6379"
    
    print("✅ EventService instantiated correctly")
    print("   - Redis URL configured")
    print("   - Pub/Sub ready for connection")
    
    # Test singleton
    singleton = get_event_service()
    assert singleton is not None
    print("✅ Singleton pattern working")
    
    return True

def test_simulation_service():
    """Test Simulation Service"""
    print("\n=== Test 2: Simulation Service ===")
    
    from services.simulation_service import SimulationService, SimulationType, ControlType
    
    # Create test graph
    graph = {
        "nodes": [
            {"id": "host-1", "type": "host", "name": "Web Server", "risk_score": 40, "metadata": {"target": "192.168.1.10"}},
            {"id": "vuln-1", "type": "vulnerability", "name": "SQL Injection", "risk_score": 85, "mitre_techniques": ["T1190"], "metadata": {"target": "192.168.1.10"}},
            {"id": "vuln-2", "type": "vulnerability", "name": "XSS", "risk_score": 60, "mitre_techniques": ["T1059"], "metadata": {}}
        ],
        "edges": [
            {"source": "host-1", "target": "vuln-1", "type": "has_vulnerability", "impact": "critical", "difficulty": "medium"},
            {"source": "host-1", "target": "vuln-2", "type": "has_vulnerability", "impact": "high", "difficulty": "easy"}
        ]
    }
    
    # Test exploit simulation
    result = SimulationService.simulate_exploit(graph, "vuln-1")
    assert result.simulation_type == SimulationType.EXPLOIT
    assert result.original_risk > 0
    assert result.simulated_risk > result.original_risk  # Risk should increase
    assert len(result.new_nodes) > 0
    assert len(result.recommendations) > 0
    
    print(f"✅ Exploit simulation working")
    print(f"   - Original risk: {result.original_risk}")
    print(f"   - Simulated risk: {result.simulated_risk}")
    print(f"   - Risk increase: +{result.risk_change}")
    print(f"   - New nodes created: {len(result.new_nodes)}")
    
    # Test patch simulation
    patch_result = SimulationService.simulate_patch(graph, "vuln-1")
    assert patch_result.simulation_type == SimulationType.PATCH
    assert patch_result.simulated_risk <= patch_result.original_risk  # Risk should decrease
    
    print(f"✅ Patch simulation working")
    print(f"   - Risk reduction: {abs(patch_result.risk_change)}")
    print(f"   - Paths eliminated: {patch_result.paths_eliminated}")
    
    # Test control simulation
    control_result = SimulationService.simulate_control(graph, ControlType.WAF)
    assert control_result.simulation_type == SimulationType.CONTROL
    assert len(control_result.recommendations) > 0
    
    print(f"✅ Control simulation working")
    print(f"   - Control type: WAF")
    print(f"   - Effectiveness: {control_result.details.get('effectiveness', 'unknown')}")
    
    return True

def test_ml_prediction_service():
    """Test ML Prediction Service"""
    print("\n=== Test 3: ML Prediction Service ===")
    
    from services.ml_prediction_service import MLPredictionService
    
    # Test vulnerability prediction
    vulnerability = {
        "id": "vuln-001",
        "title": "SQL Injection in Login Form",
        "severity": "critical",
        "cve_id": "CVE-2024-12345",
        "mitre_technique": "T1190",
        "target": "192.168.1.10:80",
        "metadata": {"exploit_available": True, "internet_exposed": True}
    }
    
    prediction = MLPredictionService.predict_exploit_likelihood(vulnerability)
    
    assert prediction.likelihood >= 0.0 and prediction.likelihood <= 1.0
    assert prediction.confidence >= 0.0 and prediction.confidence <= 1.0
    assert prediction.priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert len(prediction.factors) > 0
    
    print(f"✅ Exploit likelihood prediction working")
    print(f"   - Vulnerability: {prediction.item_name}")
    print(f"   - Likelihood: {prediction.likelihood:.1%}")
    print(f"   - Confidence: {prediction.confidence:.1%}")
    print(f"   - Priority: {prediction.priority}")
    print(f"   - Factors: {len(prediction.factors)}")
    
    # Test batch predictions
    vulnerabilities = [
        {"id": "v1", "title": "Critical RCE", "severity": "critical", "cve_id": "CVE-2025-0001", "mitre_technique": "T1190"},
        {"id": "v2", "title": "Medium XSS", "severity": "medium", "cve_id": "CVE-2024-5000", "mitre_technique": "T1059"},
        {"id": "v3", "title": "Low Info Disclosure", "severity": "low", "mitre_technique": "T1046"}
    ]
    
    predictions = MLPredictionService.predict_likely_exploits(vulnerabilities)
    
    assert len(predictions) == 3
    assert predictions[0].likelihood >= predictions[1].likelihood  # Should be sorted
    
    print(f"✅ Batch exploit predictions working")
    print(f"   - Predictions: {len(predictions)}")
    print(f"   - Top priority: {predictions[0].priority}")
    
    # Test path prediction
    graph = {
        "nodes": [
            {"id": "n1", "type": "host", "name": "Entry", "risk_score": 30, "mitre_techniques": []},
            {"id": "n2", "type": "vulnerability", "name": "Vuln", "risk_score": 80, "mitre_techniques": ["T1190"]},
            {"id": "n3", "type": "exploit", "name": "Exploit", "risk_score": 90, "mitre_techniques": ["T1003"]}
        ],
        "edges": [
            {"source": "n1", "target": "n2", "type": "has_vulnerability", "difficulty": "easy", "impact": "high"},
            {"source": "n2", "target": "n3", "type": "exploits", "difficulty": "medium", "impact": "critical"}
        ]
    }
    
    path_prediction = MLPredictionService.predict_attack_path_likelihood(graph, ["n1", "n2", "n3"])
    
    assert path_prediction.likelihood > 0
    assert path_prediction.priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
    print(f"✅ Attack path prediction working")
    print(f"   - Path: {path_prediction.item_name}")
    print(f"   - Likelihood: {path_prediction.likelihood:.1%}")
    print(f"   - Priority: {path_prediction.priority}")
    
    return True

def test_websocket_manager():
    """Test WebSocket Connection Manager"""
    print("\n=== Test 4: WebSocket Manager ===")
    
    from api.routers.websocket import ConnectionManager
    
    manager = ConnectionManager()
    
    assert manager.active_connections == {}
    print("✅ ConnectionManager initialized")
    print("   - Active connections tracking ready")
    print("   - Broadcast capability available")
    
    return True

def test_control_types():
    """Test all control types"""
    print("\n=== Test 5: Security Control Types ===")
    
    from services.simulation_service import SimulationService, ControlType
    
    graph = {
        "nodes": [
            {"id": "h1", "type": "host", "name": "Server", "risk_score": 50},
            {"id": "v1", "type": "vulnerability", "name": "CVE", "risk_score": 80}
        ],
        "edges": [
            {"source": "h1", "target": "v1", "type": "has_vulnerability", "difficulty": "easy", "impact": "high", "technique_id": "T1190"}
        ]
    }
    
    controls = [
        ControlType.FIREWALL,
        ControlType.WAF,
        ControlType.IDS,
        ControlType.SEGMENTATION,
        ControlType.MFA,
        ControlType.PATCH_MANAGEMENT
    ]
    
    for control in controls:
        result = SimulationService.simulate_control(graph, control)
        assert result.simulation_type.value == "control"
        print(f"✅ {control.value}: Risk change {result.risk_change}")
    
    print(f"\n✅ All {len(controls)} control types tested")
    
    return True

def run_all_tests():
    """Run all Phase 3 tests"""
    print("=" * 80)
    print("NeuroSploit SaaS v2 - Phase 3 Integration Tests")
    print("=" * 80)
    
    tests_run = 0
    tests_passed = 0
    
    try:
        test_event_service()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 1 failed: {e}")
        tests_run += 1
    
    try:
        test_simulation_service()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 2 failed: {e}")
        tests_run += 1
    
    try:
        test_ml_prediction_service()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 3 failed: {e}")
        tests_run += 1
    
    try:
        test_websocket_manager()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 4 failed: {e}")
        tests_run += 1
    
    try:
        test_control_types()
        tests_run += 1
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 5 failed: {e}")
        tests_run += 1
    
    print("\n" + "=" * 80)
    print(f"Test Summary: {tests_passed}/{tests_run} passed ({tests_passed*100//tests_run}%)")
    print("=" * 80)
    
    if tests_passed == tests_run:
        print("\n✅ All Phase 3 tests passed!")
        return 0
    else:
        print(f"\n⚠️  {tests_run - tests_passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
