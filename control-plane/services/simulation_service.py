"""
NeuroSploit SaaS v2 - Simulation Service
What-if analysis for attack scenarios
"""

import copy
import logging
from typing import List, Dict, Optional, Tuple
from uuid import UUID, uuid4
from dataclasses import dataclass
from enum import Enum

from .attack_graph_service import AttackGraphService

logger = logging.getLogger(__name__)

class SimulationType(str, Enum):
    EXPLOIT = "exploit"
    PATCH = "patch"
    CONTROL = "control"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"

class ControlType(str, Enum):
    FIREWALL = "firewall"
    WAF = "waf"
    IDS = "ids"
    SEGMENTATION = "segmentation"
    MFA = "mfa"
    PATCH_MANAGEMENT = "patch_management"

@dataclass
class SimulationResult:
    """Result of a simulation"""
    simulation_type: SimulationType
    target_node_id: Optional[str]
    original_risk: int
    simulated_risk: int
    risk_change: int
    paths_affected: int
    paths_eliminated: int
    new_nodes: List[Dict]
    new_edges: List[Dict]
    recommendations: List[str]
    details: Dict

class SimulationService:
    """
    Service for attack simulation and what-if analysis
    
    Enables:
    - Simulate exploiting a vulnerability
    - Simulate patching a vulnerability
    - Simulate adding security controls
    - Predict attack progression
    """
    
    @staticmethod
    def _clone_graph(graph: Dict) -> Dict:
        """Deep clone a graph for simulation"""
        return copy.deepcopy(graph)
    
    @staticmethod
    def _calculate_graph_risk(graph: Dict) -> int:
        """Calculate overall graph risk score"""
        if not graph.get("nodes"):
            return 0
        
        node_risks = [n.get("risk_score", 0) for n in graph["nodes"]]
        max_risk = max(node_risks) if node_risks else 0
        avg_risk = sum(node_risks) / len(node_risks) if node_risks else 0
        
        # Weight max risk more heavily
        return int((max_risk * 0.6) + (avg_risk * 0.4))
    
    @staticmethod
    def _find_node(graph: Dict, node_id: str) -> Optional[Dict]:
        """Find a node by ID"""
        for node in graph.get("nodes", []):
            if node.get("id") == node_id:
                return node
        return None
    
    @staticmethod
    def _count_paths(graph: Dict) -> int:
        """Count total paths in graph (approximation)"""
        # Count edges as proxy for path complexity
        return len(graph.get("edges", []))
    
    @staticmethod
    def simulate_exploit(
        graph: Dict,
        vulnerability_node_id: str
    ) -> SimulationResult:
        """
        Simulate exploiting a vulnerability
        
        What happens:
        1. Create exploit node connected to vulnerability
        2. Create access node (shell/session gained)
        3. Calculate new risk score
        4. Identify new attack paths enabled
        
        Returns:
            SimulationResult with impact analysis
        """
        sim_graph = SimulationService._clone_graph(graph)
        original_risk = SimulationService._calculate_graph_risk(graph)
        original_paths = SimulationService._count_paths(graph)
        
        # Find vulnerability node
        vuln_node = SimulationService._find_node(sim_graph, vulnerability_node_id)
        if not vuln_node:
            return SimulationResult(
                simulation_type=SimulationType.EXPLOIT,
                target_node_id=vulnerability_node_id,
                original_risk=original_risk,
                simulated_risk=original_risk,
                risk_change=0,
                paths_affected=0,
                paths_eliminated=0,
                new_nodes=[],
                new_edges=[],
                recommendations=["Vulnerability node not found"],
                details={"error": "Node not found"}
            )
        
        new_nodes = []
        new_edges = []
        
        # Create exploit node
        exploit_id = f"sim-exploit-{uuid4().hex[:8]}"
        exploit_node = {
            "id": exploit_id,
            "type": "exploit",
            "name": f"Exploited: {vuln_node.get('name', 'Unknown')}",
            "description": f"Simulated exploitation of {vuln_node.get('name', 'vulnerability')}",
            "risk_score": 90,
            "mitre_techniques": vuln_node.get("mitre_techniques", []),
            "metadata": {"simulated": True, "source_vulnerability": vulnerability_node_id}
        }
        sim_graph["nodes"].append(exploit_node)
        new_nodes.append(exploit_node)
        
        # Create edge from vulnerability to exploit
        exploit_edge = {
            "id": f"sim-edge-{uuid4().hex[:8]}",
            "source": vulnerability_node_id,
            "target": exploit_id,
            "type": "exploits",
            "technique_id": vuln_node.get("mitre_techniques", [None])[0] if vuln_node.get("mitre_techniques") else None,
            "difficulty": "medium",
            "impact": "critical"
        }
        sim_graph["edges"].append(exploit_edge)
        new_edges.append(exploit_edge)
        
        # Create access node (what attacker gains)
        target = vuln_node.get("metadata", {}).get("target", "unknown")
        access_id = f"sim-access-{uuid4().hex[:8]}"
        access_node = {
            "id": access_id,
            "type": "access",
            "name": f"Shell on {target}",
            "description": f"Remote access gained via exploitation",
            "risk_score": 85,
            "mitre_techniques": ["T1059"],  # Command and Scripting
            "metadata": {"simulated": True, "target": target}
        }
        sim_graph["nodes"].append(access_node)
        new_nodes.append(access_node)
        
        # Edge from exploit to access
        access_edge = {
            "id": f"sim-edge-{uuid4().hex[:8]}",
            "source": exploit_id,
            "target": access_id,
            "type": "grants_access",
            "technique_id": "T1059",
            "difficulty": "easy",
            "impact": "critical"
        }
        sim_graph["edges"].append(access_edge)
        new_edges.append(access_edge)
        
        # Calculate impact
        simulated_risk = SimulationService._calculate_graph_risk(sim_graph)
        simulated_paths = SimulationService._count_paths(sim_graph)
        
        recommendations = []
        risk_change = simulated_risk - original_risk
        
        if risk_change > 20:
            recommendations.append(f"🔴 CRITICAL: Exploiting this vulnerability increases risk by {risk_change} points")
            recommendations.append(f"🛡️ PATCH IMMEDIATELY: {vuln_node.get('name', 'This vulnerability')} is high-impact")
        elif risk_change > 10:
            recommendations.append(f"⚠️ HIGH: Exploitation increases risk by {risk_change} points")
            recommendations.append(f"🛡️ Schedule patching within 7 days")
        else:
            recommendations.append(f"📊 MEDIUM: Exploitation increases risk by {risk_change} points")
        
        recommendations.append(f"🎯 Attacker would gain: {access_node['name']}")
        
        return SimulationResult(
            simulation_type=SimulationType.EXPLOIT,
            target_node_id=vulnerability_node_id,
            original_risk=original_risk,
            simulated_risk=simulated_risk,
            risk_change=risk_change,
            paths_affected=simulated_paths - original_paths,
            paths_eliminated=0,
            new_nodes=new_nodes,
            new_edges=new_edges,
            recommendations=recommendations,
            details={
                "vulnerability": vuln_node.get("name"),
                "access_gained": access_node["name"],
                "target": target
            }
        )
    
    @staticmethod
    def simulate_patch(
        graph: Dict,
        vulnerability_node_id: str
    ) -> SimulationResult:
        """
        Simulate patching a vulnerability
        
        What happens:
        1. Remove vulnerability node
        2. Remove all connected edges
        3. Recalculate risk score
        4. Count eliminated attack paths
        
        Returns:
            SimulationResult with remediation impact
        """
        sim_graph = SimulationService._clone_graph(graph)
        original_risk = SimulationService._calculate_graph_risk(graph)
        original_paths = SimulationService._count_paths(graph)
        
        # Find vulnerability node
        vuln_node = SimulationService._find_node(graph, vulnerability_node_id)
        if not vuln_node:
            return SimulationResult(
                simulation_type=SimulationType.PATCH,
                target_node_id=vulnerability_node_id,
                original_risk=original_risk,
                simulated_risk=original_risk,
                risk_change=0,
                paths_affected=0,
                paths_eliminated=0,
                new_nodes=[],
                new_edges=[],
                recommendations=["Vulnerability node not found"],
                details={"error": "Node not found"}
            )
        
        # Remove node
        sim_graph["nodes"] = [
            n for n in sim_graph["nodes"]
            if n.get("id") != vulnerability_node_id
        ]
        
        # Remove connected edges
        removed_edges = [
            e for e in sim_graph["edges"]
            if e.get("source") == vulnerability_node_id or e.get("target") == vulnerability_node_id
        ]
        sim_graph["edges"] = [
            e for e in sim_graph["edges"]
            if e.get("source") != vulnerability_node_id and e.get("target") != vulnerability_node_id
        ]
        
        # Calculate impact
        simulated_risk = SimulationService._calculate_graph_risk(sim_graph)
        simulated_paths = SimulationService._count_paths(sim_graph)
        
        risk_reduction = original_risk - simulated_risk
        paths_eliminated = original_paths - simulated_paths
        
        recommendations = []
        
        if risk_reduction > 20:
            recommendations.append(f"🟢 HIGH IMPACT: Patching reduces risk by {risk_reduction} points")
            recommendations.append(f"✅ PRIORITY: Patch immediately")
        elif risk_reduction > 10:
            recommendations.append(f"🟡 MEDIUM IMPACT: Patching reduces risk by {risk_reduction} points")
            recommendations.append(f"✅ Schedule patching within 14 days")
        else:
            recommendations.append(f"📊 LOW IMPACT: Patching reduces risk by {risk_reduction} points")
        
        if paths_eliminated > 0:
            recommendations.append(f"🎯 Eliminates {paths_eliminated} attack path(s)")
        
        return SimulationResult(
            simulation_type=SimulationType.PATCH,
            target_node_id=vulnerability_node_id,
            original_risk=original_risk,
            simulated_risk=simulated_risk,
            risk_change=-risk_reduction,  # Negative because risk decreases
            paths_affected=0,
            paths_eliminated=paths_eliminated,
            new_nodes=[],
            new_edges=[],
            recommendations=recommendations,
            details={
                "vulnerability_patched": vuln_node.get("name"),
                "edges_removed": len(removed_edges),
                "risk_reduction": risk_reduction
            }
        )
    
    @staticmethod
    def simulate_control(
        graph: Dict,
        control_type: ControlType,
        target_node_id: Optional[str] = None,
        affected_edges: Optional[List[str]] = None
    ) -> SimulationResult:
        """
        Simulate adding a security control
        
        Control types:
        - FIREWALL: Block network paths
        - WAF: Block web attack edges
        - IDS: Increase difficulty of edges (detection)
        - SEGMENTATION: Remove edges between segments
        - MFA: Reduce credential-based attack impact
        - PATCH_MANAGEMENT: Reduce vulnerability risk scores
        
        Returns:
            SimulationResult with control effectiveness
        """
        sim_graph = SimulationService._clone_graph(graph)
        original_risk = SimulationService._calculate_graph_risk(graph)
        original_paths = SimulationService._count_paths(graph)
        
        recommendations = []
        edges_affected = 0
        nodes_affected = 0
        
        if control_type == ControlType.FIREWALL:
            # Firewall blocks network-level edges
            network_edge_types = ["accesses", "pivots_to", "hosts"]
            for edge in sim_graph["edges"]:
                if edge.get("type") in network_edge_types:
                    edge["impact"] = "low"
                    edge["difficulty"] = "hard"
                    edges_affected += 1
            recommendations.append(f"🔥 Firewall affects {edges_affected} network paths")
        
        elif control_type == ControlType.WAF:
            # WAF blocks web attack edges
            web_edge_types = ["exploits"]
            for edge in sim_graph["edges"]:
                if edge.get("type") in web_edge_types:
                    if edge.get("technique_id") in ["T1190", "T1059.007"]:  # Web exploits
                        edge["impact"] = "low"
                        edge["difficulty"] = "hard"
                        edges_affected += 1
            recommendations.append(f"🛡️ WAF blocks {edges_affected} web attack vectors")
        
        elif control_type == ControlType.IDS:
            # IDS increases detection chance (difficulty)
            for edge in sim_graph["edges"]:
                if edge.get("difficulty") == "easy":
                    edge["difficulty"] = "medium"
                    edges_affected += 1
                elif edge.get("difficulty") == "medium":
                    edge["difficulty"] = "hard"
                    edges_affected += 1
            recommendations.append(f"👁️ IDS increases detection on {edges_affected} attack paths")
        
        elif control_type == ControlType.SEGMENTATION:
            # Network segmentation removes lateral movement edges
            lateral_types = ["pivots_to", "accesses"]
            removed_edges = [e for e in sim_graph["edges"] if e.get("type") in lateral_types]
            sim_graph["edges"] = [e for e in sim_graph["edges"] if e.get("type") not in lateral_types]
            edges_affected = len(removed_edges)
            recommendations.append(f"🔒 Segmentation eliminates {edges_affected} lateral movement paths")
        
        elif control_type == ControlType.MFA:
            # MFA reduces credential attack impact
            credential_techniques = ["T1078", "T1110", "T1003"]
            for edge in sim_graph["edges"]:
                if edge.get("technique_id") in credential_techniques:
                    edge["impact"] = "low"
                    edge["difficulty"] = "hard"
                    edges_affected += 1
            recommendations.append(f"🔐 MFA protects against {edges_affected} credential attacks")
        
        elif control_type == ControlType.PATCH_MANAGEMENT:
            # Reduce all vulnerability node risk scores
            for node in sim_graph["nodes"]:
                if node.get("type") == "vulnerability":
                    node["risk_score"] = max(0, node.get("risk_score", 0) - 30)
                    nodes_affected += 1
            recommendations.append(f"📦 Patch management reduces risk on {nodes_affected} vulnerabilities")
        
        # Calculate impact
        simulated_risk = SimulationService._calculate_graph_risk(sim_graph)
        simulated_paths = SimulationService._count_paths(sim_graph)
        
        risk_reduction = original_risk - simulated_risk
        paths_eliminated = original_paths - simulated_paths
        
        if risk_reduction > 15:
            recommendations.append(f"🟢 HIGH EFFECTIVENESS: {control_type.value} reduces risk by {risk_reduction} points")
        elif risk_reduction > 5:
            recommendations.append(f"🟡 MEDIUM EFFECTIVENESS: {control_type.value} reduces risk by {risk_reduction} points")
        else:
            recommendations.append(f"📊 LIMITED IMPACT: {control_type.value} reduces risk by {risk_reduction} points")
        
        return SimulationResult(
            simulation_type=SimulationType.CONTROL,
            target_node_id=target_node_id,
            original_risk=original_risk,
            simulated_risk=simulated_risk,
            risk_change=-risk_reduction,
            paths_affected=edges_affected,
            paths_eliminated=paths_eliminated,
            new_nodes=[],
            new_edges=[],
            recommendations=recommendations,
            details={
                "control_type": control_type.value,
                "edges_affected": edges_affected,
                "nodes_affected": nodes_affected,
                "effectiveness": "high" if risk_reduction > 15 else "medium" if risk_reduction > 5 else "low"
            }
        )
    
    @staticmethod
    def compare_simulations(
        results: List[SimulationResult]
    ) -> Dict:
        """Compare multiple simulation results to find best remediation strategy"""
        if not results:
            return {"recommendation": "No simulations to compare"}
        
        # Sort by risk reduction (most reduction first)
        sorted_results = sorted(
            results,
            key=lambda r: r.risk_change,  # Lower is better (more negative = more reduction)
        )
        
        best = sorted_results[0]
        
        comparison = {
            "best_option": {
                "type": best.simulation_type.value,
                "target": best.target_node_id,
                "risk_reduction": abs(best.risk_change),
                "paths_eliminated": best.paths_eliminated
            },
            "all_options": [
                {
                    "type": r.simulation_type.value,
                    "target": r.target_node_id,
                    "risk_change": r.risk_change,
                    "paths_eliminated": r.paths_eliminated
                }
                for r in sorted_results
            ],
            "recommendations": [
                f"🏆 Best option: {best.simulation_type.value}",
                f"   Risk reduction: {abs(best.risk_change)} points",
                f"   Paths eliminated: {best.paths_eliminated}"
            ]
        }
        
        return comparison
