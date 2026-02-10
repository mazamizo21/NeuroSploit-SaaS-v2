#!/usr/bin/env python3
"""
TazoSploit AI Decision Engine
Autonomous decision-making for penetration testing using LLM reasoning.

Features:
- AI-powered tool selection based on findings
- Dynamic attack path planning
- Risk assessment and mitigation
- MITRE ATT&CK alignment
- Continuous learning from results
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PentestPhase(Enum):
    """Enumeration of pentest phases"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    REPORTING = "reporting"


class RiskLevel(Enum):
    """Risk levels for operations"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding"""
    finding_id: str
    timestamp: str
    phase: PentestPhase
    finding_type: str  # vulnerability, service, credential, misconfig
    target: str
    severity: RiskLevel
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    """Represents an AI-made decision"""
    decision_id: str
    timestamp: str
    phase: PentestPhase
    action: str
    tool: str
    reasoning: str
    confidence: float  # 0.0 to 1.0
    risk_level: RiskLevel
    expected_outcome: str
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """Represents a potential attack path"""
    path_id: str
    target: str
    phases: List[Tuple[PentestPhase, List[str]]]  # phase -> tools
    estimated_complexity: float
    estimated_risk: RiskLevel
    expected_impact: RiskLevel
    success_probability: float


class AIDecisionEngine:
    """
    AI-powered decision engine for autonomous penetration testing

    Uses LLM reasoning to:
    - Select appropriate tools for each phase
    - Plan attack paths
    - Assess risk and prioritize findings
    - Adapt strategies based on results
    """

    def __init__(self, llm_provider=None):
        self.llm_provider = llm_provider
        self.decisions: Dict[str, Decision] = {}
        self.findings: Dict[str, Finding] = {}
        self.attack_paths: List[AttackPath] = []
        self.learning_memory: Dict[str, Any] = {}

    def analyze_target(self, target: str, target_type: str = "web") -> List[Decision]:
        """
        Analyze target and generate initial decisions

        Args:
            target: Target URL/IP
            target_type: Type of target (web, network, cloud, mobile)

        Returns:
            List of initial decisions to execute
        """
        logger.info(f"Analyzing target: {target} (type: {target_type})")

        decisions = []

        if target_type == "web":
            decisions = self._analyze_web_target(target)
        elif target_type == "network":
            decisions = self._analyze_network_target(target)
        elif target_type == "cloud":
            decisions = self._analyze_cloud_target(target)
        else:
            logger.warning(f"Unknown target type: {target_type}")

        # Save decisions
        for decision in decisions:
            self.decisions[decision.decision_id] = decision
            logger.info(f"Decision created: {decision.action} with confidence {decision.confidence}")

        return decisions

    def _analyze_web_target(self, target: str) -> List[Decision]:
        """Analyze web target and generate decisions"""
        decisions = []

        # Phase 1: Reconnaissance
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.RECONNAISSANCE,
            action="Discover subdomains and attack surface",
            tool="subfinder, amass, httpx",
            reasoning="Web targets often have multiple subdomains and hidden endpoints. "
                     "Comprehensive reconnaissance is critical for finding all attack surface.",
            confidence=0.95,
            risk_level=RiskLevel.INFO,
            expected_outcome="Complete list of subdomains and accessible endpoints"
        ))

        # Phase 2: Technology stack identification
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.RECONNAISSANCE,
            action="Identify technology stack and frameworks",
            tool="wappalyzer, whatweb, builtwith",
            reasoning="Knowing the tech stack (server, framework, CMS, database) "
                     "guides subsequent exploitation efforts.",
            confidence=0.90,
            risk_level=RiskLevel.INFO,
            expected_outcome="Complete technology fingerprint of the target",
            dependencies=[decisions[0].decision_id]
        ))

        # Phase 3: Vulnerability scanning
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.SCANNING,
            action="Run comprehensive vulnerability scan",
            tool="nuclei, nikto, nmap",
            reasoning="Automated vulnerability scanning can quickly identify known vulnerabilities "
                     "and misconfigurations.",
            confidence=0.85,
            risk_level=RiskLevel.LOW,
            expected_outcome="List of potential vulnerabilities with severity ratings",
            dependencies=[decisions[1].decision_id]
        ))

        # Phase 4: Web application testing
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.SCANNING,
            action="Test for common web vulnerabilities",
            tool="sqlmap, burp, xsser",
            reasoning="Manual and automated testing for OWASP Top 10 vulnerabilities "
                     "(SQLi, XSS, CSRF, etc.)",
            confidence=0.80,
            risk_level=RiskLevel.MEDIUM,
            expected_outcome="Confirmed vulnerabilities with proof of concept",
            dependencies=[decisions[2].decision_id]
        ))

        return decisions

    def _analyze_network_target(self, target: str) -> List[Decision]:
        """Analyze network target and generate decisions"""
        decisions = []

        # Phase 1: Port scanning
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.SCANNING,
            action="Comprehensive port and service discovery",
            tool="nmap, masscan, rustscan",
            reasoning="Port scanning identifies open services and their versions, "
                     "providing initial attack surface.",
            confidence=0.95,
            risk_level=RiskLevel.INFO,
            expected_outcome="Complete list of open ports and running services"
        ))

        # Phase 2: Service enumeration
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.ENUMERATION,
            action="Enumerate services and gather information",
            tool="nmap scripts, enum4linux, smtp-user-enum",
            reasoning="Deep enumeration of discovered services to identify vulnerabilities "
                     "and potential attack vectors.",
            confidence=0.85,
            risk_level=RiskLevel.LOW,
            expected_outcome="Detailed information about each service configuration",
            dependencies=[decisions[0].decision_id]
        ))

        # Phase 3: Vulnerability assessment
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.SCANNING,
            action="Check for known service vulnerabilities",
            tool="searchsploit, nmap vuln scripts, nessus",
            reasoning="Check discovered services against CVE databases and exploit databases.",
            confidence=0.80,
            risk_level=RiskLevel.MEDIUM,
            expected_outcome="List of CVEs and exploits for discovered services",
            dependencies=[decisions[0].decision_id]
        ))

        return decisions

    def _analyze_cloud_target(self, target: str) -> List[Decision]:
        """Analyze cloud target and generate decisions"""
        decisions = []

        # Phase 1: Cloud enumeration
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.RECONNAISSANCE,
            action="Enumerate cloud resources and permissions",
            tool="awscli, azure-cli, gcloud, Scout2, Azurite, Prowler",
            reasoning="Cloud infrastructure requires specialized enumeration tools to identify "
                     "resources, permissions, and misconfigurations.",
            confidence=0.90,
            risk_level=RiskLevel.INFO,
            expected_outcome="Complete inventory of cloud resources and permissions"
        ))

        # Phase 2: IAM analysis
        decisions.append(Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.ENUMERATION,
            action="Analyze IAM roles and permissions",
            tool="cloudmapper, cloudsploit, Pacu",
            reasoning="IAM misconfigurations are common in cloud environments and can lead "
                     "to privilege escalation.",
            confidence=0.85,
            risk_level=RiskLevel.MEDIUM,
            expected_outcome="List of overly permissive IAM roles and policies",
            dependencies=[decisions[0].decision_id]
        ))

        return decisions

    def make_next_decision(self, current_findings: List[Finding],
                        current_phase: PentestPhase) -> Optional[Decision]:
        """
        Make the next decision based on current findings and phase

        Args:
            current_findings: List of findings from previous phases
            current_phase: Current phase of the pentest

        Returns:
            Next decision to execute, or None if no decision needed
        """
        logger.info(f"Making decision for phase: {current_phase.value}")

        # Analyze findings to determine next action
        critical_findings = [f for f in current_findings if f.severity == RiskLevel.CRITICAL]
        high_findings = [f for f in current_findings if f.severity == RiskLevel.HIGH]

        if critical_findings:
            # Prioritize exploiting critical findings
            return self._create_exploitation_decision(critical_findings[0])
        elif high_findings:
            # Exploit high severity findings
            return self._create_exploitation_decision(high_findings[0])
        else:
            # Continue with phase-specific actions
            return self._continue_phase(current_phase, current_findings)

    def _create_exploitation_decision(self, finding: Finding) -> Decision:
        """Create decision to exploit a finding"""
        return Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.EXPLOITATION,
            action=f"Exploit {finding.title}",
            tool=self._select_exploitation_tool(finding),
            reasoning=f"High/critical severity finding ({finding.title}) should be "
                     f"exploited to demonstrate impact and potentially gain access.",
            confidence=0.75,
            risk_level=RiskLevel.HIGH,
            expected_outcome="Successful exploit with elevated privileges or data access",
            metadata={"exploiting_finding_id": finding.finding_id}
        )

    def _select_exploitation_tool(self, finding: Finding) -> str:
        """Select appropriate exploitation tool based on finding type"""
        tool_mapping = {
            "sql_injection": "sqlmap",
            "xss": "xsser, burp",
            "rce": "metasploit, exploitdb",
            "privilege_escalation": "linpeas, winpeas, linux-exploit-suggester",
            "authentication_bypass": "hydra, medusa",
            "default_creds": "default-creds-checker, ncrack"
        }

        return tool_mapping.get(finding.finding_type, "metasploit")

    def _continue_phase(self, phase: PentestPhase, findings: List[Finding]) -> Optional[Decision]:
        """Determine next action for current phase"""
        phase_actions = {
            PentestPhase.RECONNAISSANCE: [
                "Run directory brute force",
                "Check for backup files",
                "Analyze robots.txt and sitemap.xml"
            ],
            PentestPhase.SCANNING: [
                "Run deeper vulnerability scan",
                "Test for common misconfigurations",
                "Check web application firewall"
            ],
            PentestPhase.ENUMERATION: [
                "Extract user accounts",
                "Gather more service details",
                "Check for default credentials"
            ]
        }

        actions = phase_actions.get(phase, [])
        if actions and len(findings) < 10:  # Continue until enough findings
            return Decision(
                decision_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                phase=phase,
                action=actions[0],
                tool=self._select_phase_tool(phase, actions[0]),
                reasoning=f"Continue {phase.value} phase with additional techniques to gather more information.",
                confidence=0.70,
                risk_level=RiskLevel.LOW,
                expected_outcome="Additional findings from extended testing"
            )

        return None

    def _select_phase_tool(self, phase: PentestPhase, action: str) -> str:
        """Select appropriate tool for phase and action"""
        tool_mapping = {
            (PentestPhase.RECONNAISSANCE, "Run directory brute force"): "gobuster, dirb, ffuf",
            (PentestPhase.RECONNAISSANCE, "Check for backup files"): "nikto, dirsearch",
            (PentestPhase.SCANNING, "Run deeper vulnerability scan"): "nuclei, vulners",
            (PentestPhase.SCANNING, "Test for common misconfigurations"): "nmap scripts, custom scripts",
            (PentestPhase.ENUMERATION, "Extract user accounts"): "enum4linux, ldapsearch"
        }

        return tool_mapping.get((phase, action), "custom tools")

    def prioritize_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Prioritize findings based on severity and exploitability

        Args:
            findings: List of findings to prioritize

        Returns:
            Sorted list of findings (highest priority first)
        """
        # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
        severity_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4
        }

        return sorted(
            findings,
            key=lambda f: (severity_order[f.severity], -len(f.evidence))
        )

    def generate_attack_path(self, target: str, findings: List[Finding]) -> AttackPath:
        """
        Generate an attack path based on findings

        Args:
            target: Target to attack
            findings: Available findings to leverage

        Returns:
            Attack path with phases and tools
        """
        logger.info(f"Generating attack path for: {target}")

        # Create attack path from critical/high findings
        critical = [f for f in findings if f.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]]

        phases = []
        if not critical:
            # Default attack path if no critical findings
            phases = [
                (PentestPhase.RECONNAISSANCE, ["subfinder", "amass"]),
                (PentestPhase.SCANNING, ["nmap", "nuclei"]),
                (PentestPhase.ENUMERATION, ["nmap scripts", "enum4linux"]),
                (PentestPhase.EXPLOITATION, ["metasploit"]),
                (PentestPhase.PRIVILEGE_ESCALATION, ["linpeas"]),
                (PentestPhase.PERSISTENCE, ["ssh-key", "cron job"]),
                (PentestPhase.EXFILTRATION, ["data exfiltration"]),
                (PentestPhase.REPORTING, ["generate report"])
            ]
        else:
            # Custom attack path based on findings
            phases = [
                (PentestPhase.EXPLOITATION, [self._select_exploitation_tool(critical[0])]),
                (PentestPhase.PRIVILEGE_ESCALATION, ["privilege escalation tools"]),
                (PentestPhase.LATERAL_MOVEMENT, ["psexec", "pass-the-hash"]),
                (PentestPhase.PERSISTENCE, ["backdoor", "registry key"]),
                (PentestPhase.EXFILTRATION, ["exfil tools"])
            ]

        attack_path = AttackPath(
            path_id=str(uuid.uuid4()),
            target=target,
            phases=phases,
            estimated_complexity=0.7,
            estimated_risk=RiskLevel.HIGH,
            expected_impact=RiskLevel.CRITICAL if critical else RiskLevel.MEDIUM,
            success_probability=0.6 if critical else 0.4
        )

        self.attack_paths.append(attack_path)
        return attack_path

    def learn_from_results(self, decision_id: str, success: bool,
                         lessons_learned: List[str]):
        """
        Learn from decision outcomes to improve future decisions

        Args:
            decision_id: ID of the decision that was executed
            success: Whether the decision was successful
            lessons_learned: List of lessons learned from execution
        """
        if decision_id not in self.decisions:
            logger.warning(f"Decision {decision_id} not found for learning")
            return

        decision = self.decisions[decision_id]

        # Store learning
        learning_record = {
            "decision_id": decision_id,
            "action": decision.action,
            "tool": decision.tool,
            "success": success,
            "lessons_learned": lessons_learned,
            "confidence_accuracy": abs(decision.confidence - (1.0 if success else 0.0)),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Store by tool type for pattern learning
        tool_type = decision.tool.split(",")[0]
        if tool_type not in self.learning_memory:
            self.learning_memory[tool_type] = []

        self.learning_memory[tool_type].append(learning_record)

        # Update decision confidence based on result
        if success:
            decision.confidence = min(1.0, decision.confidence + 0.05)
        else:
            decision.confidence = max(0.0, decision.confidence - 0.1)

        logger.info(f"Learned from decision {decision_id}: success={success}, "
                    f"lessons={len(lessons_learned)}")

    def get_decision_history(self) -> List[Dict[str, Any]]:
        """Get complete decision history"""
        return [
            {
                "decision_id": d.decision_id,
                "timestamp": d.timestamp,
                "phase": d.phase.value,
                "action": d.action,
                "tool": d.tool,
                "confidence": d.confidence,
                "risk_level": d.risk_level.value,
                "reasoning": d.reasoning
            }
            for d in self.decisions.values()
        ]

    def export_report(self) -> Dict[str, Any]:
        """
        Export comprehensive report of decisions, findings, and learning

        Returns:
            Dictionary containing all decision engine data
        """
        return {
            "summary": {
                "total_decisions": len(self.decisions),
                "total_findings": len(self.findings),
                "attack_paths_planned": len(self.attack_paths),
                "learning_records": sum(len(v) for v in self.learning_memory.values())
            },
            "decisions": self.get_decision_history(),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "timestamp": f.timestamp,
                    "phase": f.phase.value,
                    "type": f.finding_type,
                    "severity": f.severity.value,
                    "title": f.title,
                    "mitre_techniques": f.mitre_techniques
                }
                for f in self.findings.values()
            ],
            "attack_paths": [
                {
                    "path_id": p.path_id,
                    "target": p.target,
                    "phases": [
                        {"phase": phase.value, "tools": tools}
                        for phase, tools in p.phases
                    ],
                    "complexity": p.estimated_complexity,
                    "risk": p.estimated_risk.value,
                    "impact": p.expected_impact.value,
                    "success_probability": p.success_probability
                }
                for p in self.attack_paths
            ],
            "learning_memory": self.learning_memory
        }


# Example usage
if __name__ == "__main__":
    # Create decision engine
    engine = AIDecisionEngine()

    # Analyze a web target
    target = "http://example.com"
    decisions = engine.analyze_target(target, target_type="web")

    print("\n=== Initial Decisions ===")
    for decision in decisions:
        print(f"\n{decision.phase.value.upper()}: {decision.action}")
        print(f"  Tool: {decision.tool}")
        print(f"  Confidence: {decision.confidence}")
        print(f"  Risk: {decision.risk_level.value}")
        print(f"  Reasoning: {decision.reasoning}")

    # Simulate some findings
    findings = [
        Finding(
            finding_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=PentestPhase.SCANNING,
            finding_type="sql_injection",
            target=target,
            severity=RiskLevel.HIGH,
            title="SQL Injection in login form",
            description="SQL injection vulnerability found in login form",
            evidence=["Parameter 'username' is injectable"],
            mitre_techniques=["T1190"]
        )
    ]

    # Make next decision based on findings
    next_decision = engine.make_next_decision(
        findings,
        PentestPhase.SCANNING
    )

    if next_decision:
        print("\n=== Next Decision ===")
        print(f"Action: {next_decision.action}")
        print(f"Tool: {next_decision.tool}")
        print(f"Confidence: {next_decision.confidence}")

    # Generate attack path
    attack_path = engine.generate_attack_path(target, findings)

    print("\n=== Attack Path ===")
    for phase, tools in attack_path.phases:
        print(f"{phase.value}: {', '.join(tools)}")

    # Export report
    report = engine.export_report()
    print(f"\n=== Summary ===")
    print(json.dumps(report["summary"], indent=2))
