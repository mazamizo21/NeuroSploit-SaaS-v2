"""
TazoSploit SaaS v2 - Risk Scoring Service
Calculates risk scores for jobs and tenants
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class RiskScoringService:
    """Service for calculating security risk scores"""
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1
    }
    
    @staticmethod
    def calculate_job_risk_score(
        findings: List[Dict],
        targets: List[str],
        phase: str
    ) -> Dict:
        """
        Calculate comprehensive risk score for a job
        
        Returns:
            {
                "overall_score": 0-100,
                "attack_surface_score": 0-100,
                "exploitability_score": 0-100,
                "impact_score": 0-100,
                "severity_breakdown": {...},
                "risk_level": "critical|high|medium|low"
            }
        """
        
        # Calculate component scores
        attack_surface = RiskScoringService._calculate_attack_surface_score(
            findings, targets, phase
        )
        exploitability = RiskScoringService._calculate_exploitability_score(findings)
        impact = RiskScoringService._calculate_impact_score(findings)
        
        # Overall score (weighted average)
        overall = int(
            (attack_surface * 0.3) +
            (exploitability * 0.4) +
            (impact * 0.3)
        )
        
        # Severity breakdown
        severity_breakdown = RiskScoringService._get_severity_breakdown(findings)
        
        # Risk level
        risk_level = RiskScoringService._get_risk_level(overall)
        
        return {
            "overall_score": overall,
            "attack_surface_score": attack_surface,
            "exploitability_score": exploitability,
            "impact_score": impact,
            "severity_breakdown": severity_breakdown,
            "risk_level": risk_level,
            "total_findings": len(findings),
            "calculated_at": datetime.utcnow().isoformat()
        }
    
    @staticmethod
    def _calculate_attack_surface_score(
        findings: List[Dict],
        targets: List[str],
        phase: str
    ) -> int:
        """
        Calculate attack surface score (0-100)
        Based on:
        - Number of targets
        - Number of exposed services/endpoints
        - Reconnaissance findings
        """
        score = 0
        
        # Target count (more targets = larger surface)
        target_count = len(targets)
        if target_count >= 10:
            score += 30
        elif target_count >= 5:
            score += 20
        elif target_count >= 2:
            score += 10
        else:
            score += 5
        
        # Exposed services (from findings)
        exposed_services = sum(
            1 for f in findings
            if f.get("finding_type") in ["open_port", "service_detected", "endpoint_discovered"]
        )
        
        if exposed_services >= 20:
            score += 40
        elif exposed_services >= 10:
            score += 30
        elif exposed_services >= 5:
            score += 20
        else:
            score += 10
        
        # Phase factor (later phases = more surface discovered)
        phase_scores = {
            "RECON": 10,
            "VULN_SCAN": 15,
            "EXPLOIT": 20,
            "POST_EXPLOIT": 25,
            "REPORT": 30
        }
        score += phase_scores.get(phase, 10)
        
        return min(score, 100)
    
    @staticmethod
    def _calculate_exploitability_score(findings: List[Dict]) -> int:
        """
        Calculate exploitability score (0-100)
        Based on:
        - Presence of known CVEs
        - Exploit availability
        - Complexity of exploitation
        """
        score = 0
        
        # Count findings with CVEs
        cve_findings = [f for f in findings if f.get("cve_id")]
        
        if len(cve_findings) >= 10:
            score += 50
        elif len(cve_findings) >= 5:
            score += 40
        elif len(cve_findings) >= 2:
            score += 30
        elif len(cve_findings) >= 1:
            score += 20
        
        # Critical/High severity findings (easier to exploit)
        critical_high = sum(
            1 for f in findings
            if f.get("severity") in ["critical", "high"]
        )
        
        if critical_high >= 5:
            score += 50
        elif critical_high >= 3:
            score += 35
        elif critical_high >= 1:
            score += 20
        
        return min(score, 100)
    
    @staticmethod
    def _calculate_impact_score(findings: List[Dict]) -> int:
        """
        Calculate impact score (0-100)
        Based on:
        - Severity of findings
        - Number of critical findings
        - Potential business impact
        """
        if not findings:
            return 0
        
        # Weighted severity score
        total_weight = 0
        for finding in findings:
            severity = finding.get("severity", "info")
            total_weight += RiskScoringService.SEVERITY_WEIGHTS.get(severity, 1)
        
        # Normalize to 0-100
        max_possible = len(findings) * 10  # All critical
        score = int((total_weight / max_possible) * 100) if max_possible > 0 else 0
        
        # Boost for critical findings
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        if critical_count >= 3:
            score = min(score + 20, 100)
        elif critical_count >= 1:
            score = min(score + 10, 100)
        
        return score
    
    @staticmethod
    def _get_severity_breakdown(findings: List[Dict]) -> Dict[str, int]:
        """Get count of findings by severity"""
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    @staticmethod
    def _get_risk_level(score: int) -> str:
        """Convert numeric score to risk level"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"
    
    @staticmethod
    def calculate_trend_data(
        historical_scores: List[Dict],
        days: int = 30
    ) -> Dict:
        """
        Calculate risk trend over time
        
        Args:
            historical_scores: List of {date, score} dicts
            days: Number of days to analyze
        
        Returns:
            {
                "trend": "improving|worsening|stable",
                "average_score": float,
                "score_change": int,
                "data_points": [...]
            }
        """
        if not historical_scores:
            return {
                "trend": "stable",
                "average_score": 0,
                "score_change": 0,
                "data_points": []
            }
        
        # Sort by date
        sorted_scores = sorted(historical_scores, key=lambda x: x["date"])
        
        # Calculate average
        avg_score = sum(s["score"] for s in sorted_scores) / len(sorted_scores)
        
        # Calculate trend (compare first half to second half)
        mid_point = len(sorted_scores) // 2
        if mid_point > 0:
            first_half_avg = sum(s["score"] for s in sorted_scores[:mid_point]) / mid_point
            second_half_avg = sum(s["score"] for s in sorted_scores[mid_point:]) / (len(sorted_scores) - mid_point)
            
            score_change = int(second_half_avg - first_half_avg)
            
            if score_change <= -10:
                trend = "improving"  # Score going down = risk improving
            elif score_change >= 10:
                trend = "worsening"
            else:
                trend = "stable"
        else:
            trend = "stable"
            score_change = 0
        
        return {
            "trend": trend,
            "average_score": round(avg_score, 1),
            "score_change": score_change,
            "data_points": sorted_scores
        }
    
    @staticmethod
    def generate_recommendations(
        risk_score: Dict,
        findings: List[Dict]
    ) -> List[str]:
        """Generate actionable recommendations based on risk score"""
        recommendations = []
        
        overall = risk_score["overall_score"]
        severity = risk_score["severity_breakdown"]
        
        # Critical findings
        if severity["critical"] > 0:
            recommendations.append(
                f"🔴 URGENT: Address {severity['critical']} critical finding(s) immediately. "
                "These pose immediate risk to your security."
            )
        
        # High severity
        if severity["high"] >= 3:
            recommendations.append(
                f"⚠️ HIGH PRIORITY: Remediate {severity['high']} high-severity findings "
                "within the next 7 days."
            )
        
        # Attack surface
        if risk_score["attack_surface_score"] >= 70:
            recommendations.append(
                "🎯 Reduce attack surface by closing unnecessary ports and services. "
                "Review all exposed endpoints."
            )
        
        # Exploitability
        if risk_score["exploitability_score"] >= 70:
            recommendations.append(
                "🛡️ Patch known vulnerabilities immediately. Multiple CVEs detected with "
                "available exploits."
            )
        
        # Overall risk
        if overall >= 80:
            recommendations.append(
                "⚡ CRITICAL RISK LEVEL: Implement emergency response plan. "
                "Consider taking affected systems offline until remediation."
            )
        elif overall >= 60:
            recommendations.append(
                "⚠️ HIGH RISK: Prioritize security improvements. Schedule remediation "
                "within 2 weeks."
            )
        
        # General recommendations
        if not recommendations:
            recommendations.append(
                "✅ Continue monitoring and maintain current security posture. "
                "Schedule regular assessments."
            )
        
        return recommendations
