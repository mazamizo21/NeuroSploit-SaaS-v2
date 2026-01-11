"""
NeuroSploit SaaS v2 - ML Prediction Service
Machine learning for attack path prediction
"""

import logging
import math
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class PredictionResult:
    """Result of ML prediction"""
    item_id: str
    item_name: str
    likelihood: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    factors: List[str]  # Reasons for prediction
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW

class MLPredictionService:
    """
    Machine learning service for predicting attack behavior
    
    Uses statistical models to predict:
    - Which vulnerabilities will be exploited
    - Most likely attack paths
    - Time to exploitation
    - Attacker behavior patterns
    
    Note: This is a lightweight implementation using statistical methods.
    For production, integrate with scikit-learn or similar ML library.
    """
    
    # Weights for exploit likelihood calculation
    SEVERITY_WEIGHTS = {
        "critical": 0.95,
        "high": 0.80,
        "medium": 0.50,
        "low": 0.20,
        "info": 0.05
    }
    
    # CVE age factors (older = more likely exploited)
    AGE_FACTORS = {
        "new": 0.6,      # < 30 days
        "recent": 0.8,   # 30-180 days  
        "mature": 0.95,  # 180-365 days
        "old": 0.85      # > 365 days (slightly less as may be patched)
    }
    
    # Service type risk factors
    SERVICE_RISK = {
        "ssh": 0.7,
        "ftp": 0.8,
        "http": 0.85,
        "https": 0.75,
        "smb": 0.9,
        "rdp": 0.85,
        "mysql": 0.8,
        "postgresql": 0.75,
        "mssql": 0.85,
        "redis": 0.7,
        "mongodb": 0.75,
        "elasticsearch": 0.8,
        "default": 0.5
    }
    
    # MITRE technique exploit likelihood
    TECHNIQUE_LIKELIHOOD = {
        "T1190": 0.9,   # Exploit Public-Facing Application
        "T1133": 0.85,  # External Remote Services
        "T1078": 0.8,   # Valid Accounts
        "T1110": 0.75,  # Brute Force
        "T1046": 0.7,   # Network Service Discovery
        "T1059": 0.85,  # Command and Scripting
        "T1003": 0.9,   # Credential Dumping
        "T1021": 0.8,   # Remote Services
        "T1068": 0.85,  # Exploitation for Privilege Escalation
        "default": 0.5
    }
    
    @staticmethod
    def predict_exploit_likelihood(
        vulnerability: Dict,
        context: Optional[Dict] = None
    ) -> PredictionResult:
        """
        Predict likelihood that a vulnerability will be exploited
        
        Factors considered:
        1. Severity (CVSS score)
        2. CVE age
        3. Exploit availability
        4. Target service type
        5. Network exposure
        6. MITRE technique association
        
        Returns:
            PredictionResult with likelihood 0.0-1.0
        """
        factors = []
        scores = []
        
        # Factor 1: Severity
        severity = vulnerability.get("severity", "medium").lower()
        severity_score = MLPredictionService.SEVERITY_WEIGHTS.get(severity, 0.5)
        scores.append(severity_score)
        factors.append(f"Severity ({severity}): {severity_score:.0%}")
        
        # Factor 2: CVE age (if available)
        cve_id = vulnerability.get("cve_id")
        if cve_id:
            # Extract year from CVE-YYYY-XXXX
            try:
                year = int(cve_id.split("-")[1])
                current_year = 2026
                age_years = current_year - year
                if age_years < 1:
                    age_score = MLPredictionService.AGE_FACTORS["new"]
                    factors.append(f"CVE age (new): {age_score:.0%}")
                elif age_years < 2:
                    age_score = MLPredictionService.AGE_FACTORS["recent"]
                    factors.append(f"CVE age (recent): {age_score:.0%}")
                elif age_years < 3:
                    age_score = MLPredictionService.AGE_FACTORS["mature"]
                    factors.append(f"CVE age (mature): {age_score:.0%}")
                else:
                    age_score = MLPredictionService.AGE_FACTORS["old"]
                    factors.append(f"CVE age (old): {age_score:.0%}")
                scores.append(age_score)
            except:
                pass
        
        # Factor 3: Exploit availability
        metadata = vulnerability.get("metadata", {})
        if metadata.get("exploit_available") or metadata.get("metasploit_module"):
            exploit_score = 0.95
            factors.append(f"Exploit available: {exploit_score:.0%}")
            scores.append(exploit_score)
        
        # Factor 4: Service type
        service = vulnerability.get("service", "").lower()
        if not service:
            # Try to extract from target or metadata
            target = vulnerability.get("target", "")
            if ":" in target:
                port = target.split(":")[-1]
                port_to_service = {
                    "22": "ssh", "21": "ftp", "80": "http", "443": "https",
                    "445": "smb", "3389": "rdp", "3306": "mysql", "5432": "postgresql",
                    "1433": "mssql", "6379": "redis", "27017": "mongodb"
                }
                service = port_to_service.get(port, "default")
        
        service_score = MLPredictionService.SERVICE_RISK.get(service, MLPredictionService.SERVICE_RISK["default"])
        scores.append(service_score)
        factors.append(f"Service type ({service}): {service_score:.0%}")
        
        # Factor 5: MITRE technique
        technique = vulnerability.get("mitre_technique")
        if technique:
            tech_score = MLPredictionService.TECHNIQUE_LIKELIHOOD.get(
                technique, 
                MLPredictionService.TECHNIQUE_LIKELIHOOD["default"]
            )
            scores.append(tech_score)
            factors.append(f"MITRE technique ({technique}): {tech_score:.0%}")
        
        # Factor 6: Network exposure
        if metadata.get("internet_exposed") or metadata.get("public_facing"):
            exposure_score = 0.9
            factors.append(f"Internet exposed: {exposure_score:.0%}")
            scores.append(exposure_score)
        
        # Calculate weighted average likelihood
        if scores:
            likelihood = sum(scores) / len(scores)
        else:
            likelihood = 0.5
        
        # Adjust confidence based on number of factors
        confidence = min(0.95, len(scores) * 0.15)
        
        # Determine priority
        if likelihood >= 0.8:
            priority = "CRITICAL"
        elif likelihood >= 0.6:
            priority = "HIGH"
        elif likelihood >= 0.4:
            priority = "MEDIUM"
        else:
            priority = "LOW"
        
        return PredictionResult(
            item_id=vulnerability.get("id", "unknown"),
            item_name=vulnerability.get("title", vulnerability.get("name", "Unknown")),
            likelihood=round(likelihood, 3),
            confidence=round(confidence, 3),
            factors=factors,
            priority=priority
        )
    
    @staticmethod
    def predict_attack_path_likelihood(
        graph: Dict,
        path: List[str]
    ) -> PredictionResult:
        """
        Predict likelihood of an attack path being used
        
        Factors:
        1. Path length (shorter = more likely)
        2. Node risk scores along path
        3. Edge difficulties
        4. Path to critical asset
        
        Returns:
            PredictionResult with path likelihood
        """
        if not path or len(path) < 2:
            return PredictionResult(
                item_id="empty_path",
                item_name="Empty Path",
                likelihood=0.0,
                confidence=0.0,
                factors=["Invalid path"],
                priority="LOW"
            )
        
        factors = []
        scores = []
        
        # Get nodes and edges
        node_map = {n["id"]: n for n in graph.get("nodes", [])}
        edge_map = {}
        for e in graph.get("edges", []):
            key = f"{e['source']}->{e['target']}"
            edge_map[key] = e
        
        # Factor 1: Path length
        path_length = len(path)
        if path_length <= 3:
            length_score = 0.9
            factors.append(f"Short path ({path_length} hops): {length_score:.0%}")
        elif path_length <= 5:
            length_score = 0.7
            factors.append(f"Medium path ({path_length} hops): {length_score:.0%}")
        else:
            length_score = max(0.3, 1.0 - (path_length * 0.1))
            factors.append(f"Long path ({path_length} hops): {length_score:.0%}")
        scores.append(length_score)
        
        # Factor 2: Node risk scores
        node_risks = []
        for node_id in path:
            node = node_map.get(node_id, {})
            risk = node.get("risk_score", 50) / 100
            node_risks.append(risk)
        
        avg_node_risk = sum(node_risks) / len(node_risks) if node_risks else 0.5
        scores.append(avg_node_risk)
        factors.append(f"Average node risk: {avg_node_risk:.0%}")
        
        # Factor 3: Edge difficulties
        edge_scores = []
        difficulty_map = {"easy": 0.9, "medium": 0.6, "hard": 0.3}
        
        for i in range(len(path) - 1):
            edge_key = f"{path[i]}->{path[i+1]}"
            edge = edge_map.get(edge_key, {})
            difficulty = edge.get("difficulty", "medium")
            edge_scores.append(difficulty_map.get(difficulty, 0.6))
        
        if edge_scores:
            avg_edge_score = sum(edge_scores) / len(edge_scores)
            scores.append(avg_edge_score)
            factors.append(f"Average edge accessibility: {avg_edge_score:.0%}")
        
        # Factor 4: Contains critical techniques
        critical_techniques = {"T1190", "T1078", "T1003", "T1068"}
        has_critical = False
        for node_id in path:
            node = node_map.get(node_id, {})
            techniques = node.get("mitre_techniques", [])
            if any(t in critical_techniques for t in techniques):
                has_critical = True
                break
        
        if has_critical:
            critical_score = 0.85
            scores.append(critical_score)
            factors.append(f"Contains critical technique: {critical_score:.0%}")
        
        # Calculate likelihood
        likelihood = sum(scores) / len(scores) if scores else 0.5
        confidence = min(0.9, len(scores) * 0.2)
        
        # Priority
        if likelihood >= 0.75:
            priority = "CRITICAL"
        elif likelihood >= 0.55:
            priority = "HIGH"
        elif likelihood >= 0.35:
            priority = "MEDIUM"
        else:
            priority = "LOW"
        
        path_name = f"{path[0]} → ... → {path[-1]}"
        
        return PredictionResult(
            item_id=f"path-{path[0]}-{path[-1]}",
            item_name=path_name,
            likelihood=round(likelihood, 3),
            confidence=round(confidence, 3),
            factors=factors,
            priority=priority
        )
    
    @staticmethod
    def predict_likely_exploits(
        vulnerabilities: List[Dict]
    ) -> List[PredictionResult]:
        """
        Predict which vulnerabilities are most likely to be exploited
        
        Returns sorted list by likelihood (highest first)
        """
        predictions = []
        
        for vuln in vulnerabilities:
            prediction = MLPredictionService.predict_exploit_likelihood(vuln)
            predictions.append(prediction)
        
        # Sort by likelihood descending
        predictions.sort(key=lambda p: p.likelihood, reverse=True)
        
        return predictions
    
    @staticmethod
    def predict_attack_paths(
        graph: Dict,
        max_paths: int = 10
    ) -> List[PredictionResult]:
        """
        Predict most likely attack paths in the graph
        
        Returns sorted list of path predictions
        """
        from .attack_graph_service import AttackGraphService
        
        predictions = []
        
        # Find entry points (nodes with no incoming edges)
        incoming = set(e["target"] for e in graph.get("edges", []))
        entry_points = [n["id"] for n in graph.get("nodes", []) if n["id"] not in incoming]
        
        # Find high-value targets (high risk score nodes)
        targets = [
            n["id"] for n in graph.get("nodes", [])
            if n.get("risk_score", 0) >= 70 or n.get("type") in ["exploit", "credential", "data"]
        ]
        
        # Find paths from entries to targets
        for entry in entry_points[:5]:  # Limit entries to check
            for target in targets[:5]:  # Limit targets to check
                if entry != target:
                    paths = AttackGraphService.find_all_paths(graph, entry, target, max_hops=6)
                    for path in paths[:3]:  # Limit paths per pair
                        prediction = MLPredictionService.predict_attack_path_likelihood(graph, path)
                        predictions.append(prediction)
        
        # Sort by likelihood
        predictions.sort(key=lambda p: p.likelihood, reverse=True)
        
        return predictions[:max_paths]
    
    @staticmethod
    def get_threat_summary(
        graph: Dict,
        vulnerabilities: List[Dict]
    ) -> Dict:
        """
        Generate comprehensive threat summary using ML predictions
        """
        # Predict exploit likelihood
        exploit_predictions = MLPredictionService.predict_likely_exploits(vulnerabilities)
        
        # Predict attack paths
        path_predictions = MLPredictionService.predict_attack_paths(graph)
        
        # Categorize by priority
        critical_vulns = [p for p in exploit_predictions if p.priority == "CRITICAL"]
        high_vulns = [p for p in exploit_predictions if p.priority == "HIGH"]
        
        critical_paths = [p for p in path_predictions if p.priority == "CRITICAL"]
        high_paths = [p for p in path_predictions if p.priority == "HIGH"]
        
        return {
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "critical_likelihood_vulns": len(critical_vulns),
                "high_likelihood_vulns": len(high_vulns),
                "total_attack_paths": len(path_predictions),
                "critical_paths": len(critical_paths),
                "high_priority_paths": len(high_paths)
            },
            "top_exploit_targets": [
                {
                    "id": p.item_id,
                    "name": p.item_name,
                    "likelihood": p.likelihood,
                    "priority": p.priority,
                    "factors": p.factors[:3]  # Top 3 factors
                }
                for p in exploit_predictions[:5]
            ],
            "top_attack_paths": [
                {
                    "path": p.item_name,
                    "likelihood": p.likelihood,
                    "priority": p.priority,
                    "factors": p.factors[:3]
                }
                for p in path_predictions[:5]
            ],
            "recommendations": [
                f"🔴 {len(critical_vulns)} vulnerabilities with >80% exploit likelihood",
                f"🎯 {len(critical_paths)} attack paths with >75% likelihood",
                f"🛡️ Focus on: {critical_vulns[0].item_name if critical_vulns else 'N/A'}",
                f"📊 Overall threat level: {'CRITICAL' if critical_vulns else 'HIGH' if high_vulns else 'MEDIUM'}"
            ]
        }
