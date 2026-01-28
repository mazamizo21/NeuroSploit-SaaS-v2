"""
TazoSploit SaaS v2 - Attack Graph Service
Build and analyze attack paths from pentest findings
"""

import logging
from typing import List, Dict, Optional, Tuple
from uuid import UUID
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class AttackGraphService:
    """Service for building and analyzing attack graphs"""
    
    @staticmethod
    def build_graph_from_findings(
        job_id: UUID,
        findings: List[Dict],
        targets: List[str]
    ) -> Dict:
        """
        Build attack graph from job findings
        
        Args:
            job_id: Job UUID
            findings: List of finding dictionaries
            targets: List of target IPs/hostnames
        
        Returns:
            Dictionary with nodes, edges, and metadata
        """
        nodes = []
        edges = []
        node_id_map = {}  # Map (type, name) -> node_id
        
        # Create initial target nodes
        for target in targets:
            node_id = f"host-{target}"
            node_id_map[("host", target)] = node_id
            nodes.append({
                "id": node_id,
                "type": "host",
                "name": target,
                "description": f"Target host: {target}",
                "risk_score": 0,
                "mitre_techniques": [],
                "metadata": {"is_target": True}
            })
        
        # Process findings to create nodes and edges
        for finding in findings:
            finding_type = finding.get("finding_type", "unknown")
            target = finding.get("target", "unknown")
            severity = finding.get("severity", "info")
            mitre_technique = finding.get("mitre_technique")
            
            # Map severity to risk score
            severity_scores = {
                "critical": 90,
                "high": 75,
                "medium": 50,
                "low": 25,
                "info": 10
            }
            risk_score = severity_scores.get(severity, 10)
            
            # Create nodes based on finding type
            if finding_type in ["open_port", "service_detected"]:
                # Service node
                service_name = finding.get("title", "Unknown Service")
                node_id = f"service-{target}-{service_name}"
                
                if (finding_type, node_id) not in node_id_map:
                    node_id_map[(finding_type, node_id)] = node_id
                    nodes.append({
                        "id": node_id,
                        "type": "service",
                        "name": service_name,
                        "description": finding.get("description", ""),
                        "risk_score": risk_score,
                        "mitre_techniques": [mitre_technique] if mitre_technique else [],
                        "metadata": {
                            "target": target,
                            "port": finding.get("metadata", {}).get("port"),
                            "protocol": finding.get("metadata", {}).get("protocol")
                        }
                    })
                    
                    # Edge from host to service
                    host_node_id = node_id_map.get(("host", target))
                    if host_node_id:
                        edges.append({
                            "id": f"edge-{host_node_id}-{node_id}",
                            "source": host_node_id,
                            "target": node_id,
                            "type": "hosts",
                            "technique_id": mitre_technique,
                            "difficulty": "easy",
                            "impact": "low"
                        })
            
            elif finding_type in ["vulnerability", "cve"]:
                # Vulnerability node
                vuln_name = finding.get("title", "Unknown Vulnerability")
                node_id = f"vuln-{target}-{finding.get('cve_id', vuln_name)}"
                
                if (finding_type, node_id) not in node_id_map:
                    node_id_map[(finding_type, node_id)] = node_id
                    nodes.append({
                        "id": node_id,
                        "type": "vulnerability",
                        "name": vuln_name,
                        "description": finding.get("description", ""),
                        "risk_score": risk_score,
                        "mitre_techniques": [mitre_technique] if mitre_technique else [],
                        "metadata": {
                            "target": target,
                            "cve_id": finding.get("cve_id"),
                            "cwe_id": finding.get("cwe_id"),
                            "cvss_score": finding.get("metadata", {}).get("cvss_score")
                        }
                    })
                    
                    # Edge from service/host to vulnerability
                    source_node_id = node_id_map.get(("host", target))
                    if source_node_id:
                        edges.append({
                            "id": f"edge-{source_node_id}-{node_id}",
                            "source": source_node_id,
                            "target": node_id,
                            "type": "has_vulnerability",
                            "technique_id": mitre_technique,
                            "difficulty": "medium",
                            "impact": severity
                        })
            
            elif finding_type in ["exploit", "successful_exploit"]:
                # Exploit node
                exploit_name = finding.get("title", "Exploit")
                node_id = f"exploit-{target}-{exploit_name}"
                
                if (finding_type, node_id) not in node_id_map:
                    node_id_map[(finding_type, node_id)] = node_id
                    nodes.append({
                        "id": node_id,
                        "type": "exploit",
                        "name": exploit_name,
                        "description": finding.get("description", ""),
                        "risk_score": risk_score,
                        "mitre_techniques": [mitre_technique] if mitre_technique else [],
                        "metadata": {
                            "target": target,
                            "exploit_type": finding.get("metadata", {}).get("exploit_type")
                        }
                    })
                    
                    # Edge from vulnerability to exploit
                    # Try to find related vulnerability
                    vuln_node_id = None
                    for key, nid in node_id_map.items():
                        if key[0] == "vulnerability" and target in key[1]:
                            vuln_node_id = nid
                            break
                    
                    if vuln_node_id:
                        edges.append({
                            "id": f"edge-{vuln_node_id}-{node_id}",
                            "source": vuln_node_id,
                            "target": node_id,
                            "type": "exploits",
                            "technique_id": mitre_technique,
                            "difficulty": "hard",
                            "impact": "critical"
                        })
        
        return {
            "job_id": str(job_id),
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges)
        }
    
    @staticmethod
    def find_all_paths(
        graph: Dict,
        start_node_id: str,
        end_node_id: str,
        max_hops: int = 10
    ) -> List[List[str]]:
        """
        Find all paths from start to end node using BFS
        
        Args:
            graph: Graph dictionary with nodes and edges
            start_node_id: Starting node ID
            end_node_id: Ending node ID
            max_hops: Maximum path length
        
        Returns:
            List of paths (each path is list of node IDs)
        """
        # Build adjacency list
        adjacency = defaultdict(list)
        for edge in graph["edges"]:
            adjacency[edge["source"]].append(edge["target"])
        
        # BFS to find all paths
        paths = []
        queue = deque([(start_node_id, [start_node_id])])
        
        while queue:
            current_node, path = queue.popleft()
            
            # Check if we reached the end
            if current_node == end_node_id:
                paths.append(path)
                continue
            
            # Check max hops
            if len(path) >= max_hops:
                continue
            
            # Explore neighbors
            for neighbor in adjacency[current_node]:
                if neighbor not in path:  # Avoid cycles
                    queue.append((neighbor, path + [neighbor]))
        
        return paths
    
    @staticmethod
    def calculate_path_risk(
        graph: Dict,
        path_node_ids: List[str]
    ) -> int:
        """
        Calculate risk score for a path
        
        Formula:
        Path Risk = (Avg Node Risk * 0.4) + 
                    (Max Edge Impact * 0.4) + 
                    (Path Length Penalty * 0.2)
        
        Returns:
            Risk score (0-100)
        """
        if not path_node_ids:
            return 0
        
        # Get nodes in path
        node_map = {n["id"]: n for n in graph["nodes"]}
        path_nodes = [node_map[nid] for nid in path_node_ids if nid in node_map]
        
        if not path_nodes:
            return 0
        
        # Calculate average node risk
        node_risks = [n.get("risk_score", 0) for n in path_nodes]
        avg_node_risk = sum(node_risks) / len(node_risks)
        
        # Find edges in path
        edge_impacts = {"low": 25, "medium": 50, "high": 75, "critical": 100}
        max_impact = 0
        
        for i in range(len(path_node_ids) - 1):
            source = path_node_ids[i]
            target = path_node_ids[i + 1]
            
            for edge in graph["edges"]:
                if edge["source"] == source and edge["target"] == target:
                    impact_score = edge_impacts.get(edge.get("impact", "medium"), 50)
                    max_impact = max(max_impact, impact_score)
        
        # Path length penalty (longer = harder to execute = lower risk)
        length_penalty = max(0, 100 - (len(path_node_ids) * 10))
        
        # Calculate final score
        risk_score = int(
            (avg_node_risk * 0.4) + 
            (max_impact * 0.4) + 
            (length_penalty * 0.2)
        )
        
        return min(100, max(0, risk_score))
    
    @staticmethod
    def identify_critical_paths(
        graph: Dict,
        critical_assets: List[Dict],
        max_paths: int = 10
    ) -> List[Dict]:
        """
        Find paths leading to critical assets
        
        Args:
            graph: Attack graph
            critical_assets: List of critical asset definitions
            max_paths: Maximum number of paths to return
        
        Returns:
            List of path dictionaries sorted by risk
        """
        critical_paths = []
        
        # Find nodes matching critical assets
        critical_node_ids = []
        for node in graph["nodes"]:
            for asset in critical_assets:
                # Match by identifiers
                identifiers = asset.get("identifiers", {})
                node_metadata = node.get("metadata", {})
                
                # Check if node matches asset
                if (node_metadata.get("target") in identifiers.values() or
                    node.get("name") in identifiers.values()):
                    critical_node_ids.append(node["id"])
        
        # Find all entry points (nodes with no incoming edges)
        incoming_edges = set(e["target"] for e in graph["edges"])
        entry_points = [n["id"] for n in graph["nodes"] if n["id"] not in incoming_edges]
        
        # Find paths from entry points to critical nodes
        for entry in entry_points:
            for critical_node in critical_node_ids:
                paths = AttackGraphService.find_all_paths(
                    graph, entry, critical_node, max_hops=8
                )
                
                for path in paths:
                    risk_score = AttackGraphService.calculate_path_risk(graph, path)
                    critical_paths.append({
                        "path_nodes": path,
                        "risk_score": risk_score,
                        "length": len(path),
                        "start_node": entry,
                        "end_node": critical_node,
                        "is_critical": True
                    })
        
        # Sort by risk score and return top paths
        critical_paths.sort(key=lambda p: p["risk_score"], reverse=True)
        return critical_paths[:max_paths]
    
    @staticmethod
    def generate_recommendations(
        paths: List[Dict],
        graph: Dict
    ) -> List[str]:
        """Generate remediation recommendations based on attack paths"""
        recommendations = []
        
        if not paths:
            return ["✅ No critical attack paths identified"]
        
        # Analyze highest risk path
        highest_risk_path = max(paths, key=lambda p: p["risk_score"])
        
        recommendations.append(
            f"🔴 CRITICAL: Highest risk attack path has {highest_risk_path['length']} hops "
            f"with risk score {highest_risk_path['risk_score']}/100"
        )
        
        # Find common nodes (pivot points)
        node_frequency = defaultdict(int)
        for path in paths:
            for node_id in path["path_nodes"]:
                node_frequency[node_id] += 1
        
        # Identify pivot points (nodes in multiple paths)
        pivot_points = [(nid, count) for nid, count in node_frequency.items() if count > 1]
        pivot_points.sort(key=lambda x: x[1], reverse=True)
        
        if pivot_points:
            node_map = {n["id"]: n for n in graph["nodes"]}
            top_pivot = pivot_points[0]
            pivot_node = node_map.get(top_pivot[0])
            
            if pivot_node:
                recommendations.append(
                    f"🎯 PIVOT POINT: '{pivot_node['name']}' appears in {top_pivot[1]} attack paths. "
                    f"Securing this node will disrupt multiple attack chains."
                )
        
        # Recommend patching high-risk vulnerabilities
        vuln_nodes = [n for n in graph["nodes"] if n["type"] == "vulnerability" and n["risk_score"] >= 70]
        if vuln_nodes:
            recommendations.append(
                f"🛡️ PATCH PRIORITY: {len(vuln_nodes)} high-risk vulnerabilities identified. "
                f"Patch these to eliminate attack vectors."
            )
        
        # Recommend network segmentation
        if len(paths) > 5:
            recommendations.append(
                "🔒 NETWORK SEGMENTATION: Multiple attack paths detected. "
                "Implement network segmentation to limit lateral movement."
            )
        
        return recommendations
