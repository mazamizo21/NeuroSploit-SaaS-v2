#!/usr/bin/env python3
"""
TazoSploit Multi-Agent Session Management
Manages multi-agent sessions with communication and coordination.

Features:
- Multi-agent session management
- Inter-agent communication
- Finding merging across agents
- Session state tracking and persistence
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import os

from orchestrator import AgentOrchestrator, AgentTask, AgentResult, AgentStatus


class SessionStatus(Enum):
    """Multi-agent session status"""
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Finding:
    """Represents a security finding from any agent"""
    finding_id: str
    agent_id: str
    task_id: str
    timestamp: str
    finding_type: str  # vulnerability, credential, misconfig, etc.
    target: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "finding_id": self.finding_id,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "timestamp": self.timestamp,
            "type": self.finding_type,
            "target": self.target,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "references": self.references,
            "mitre_techniques": self.mitre_techniques,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create finding from dictionary"""
        return cls(**data)


@dataclass
class AgentMessage:
    """Message between agents"""
    message_id: str
    from_agent: str
    to_agent: str
    timestamp: str
    message_type: str  # finding, status, request, response
    content: Dict[str, Any]
    reply_to: Optional[str] = None


@dataclass
class MultiAgentSession:
    """Represents a multi-agent pentest session"""
    session_id: str
    target: str
    objective: str
    status: SessionStatus
    created_at: str
    orchestrator: AgentOrchestrator
    findings: List[Finding] = field(default_factory=list)
    messages: List[AgentMessage] = field(default_factory=list)
    agents_status: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding):
        """Add a finding to the session"""
        self.findings.append(finding)
    
    def add_message(self, message: AgentMessage):
        """Add a message to the session"""
        self.messages.append(message)
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity"""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_type(self, finding_type: str) -> List[Finding]:
        """Get findings filtered by type"""
        return [f for f in self.findings if f.finding_type == finding_type]
    
    def get_findings_by_agent(self, agent_id: str) -> List[Finding]:
        """Get findings from a specific agent"""
        return [f for f in self.findings if f.agent_id == agent_id]


class MultiAgentManager:
    """
    Manages multi-agent sessions with communication and coordination.
    Handles finding merging, deduplication, and state management.
    """
    
    def __init__(self, storage_dir: str = "/pentest/sessions"):
        self.storage_dir = storage_dir
        self.sessions: Dict[str, MultiAgentSession] = {}
        self.message_handlers: Dict[str, List[Callable]] = {}
        
        os.makedirs(storage_dir, exist_ok=True)
    
    def create_session(self, target: str, objective: str, 
                      skills: List[str] = None) -> MultiAgentSession:
        """Create a new multi-agent session"""
        session_id = str(uuid.uuid4())
        
        # Create orchestrator for this session
        orchestrator = AgentOrchestrator()
        
        session = MultiAgentSession(
            session_id=session_id,
            target=target,
            objective=objective,
            status=SessionStatus.INITIALIZING,
            created_at=datetime.now(timezone.utc).isoformat(),
            orchestrator=orchestrator,
            metadata={"skills_requested": skills or []}
        )
        
        self.sessions[session_id] = session
        self._save_session(session)
        
        return session
    
    def get_session(self, session_id: str) -> Optional[MultiAgentSession]:
        """Get a session by ID"""
        return self.sessions.get(session_id)
    
    def get_all_sessions(self) -> List[MultiAgentSession]:
        """Get all sessions"""
        return list(self.sessions.values())
    
    def start_session(self, session_id: str) -> bool:
        """Start a session execution"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        session.status = SessionStatus.RUNNING
        session.metadata["started_at"] = datetime.now(timezone.utc).isoformat()
        
        self._save_session(session)
        return True
    
    def pause_session(self, session_id: str) -> bool:
        """Pause a running session"""
        session = self.get_session(session_id)
        if not session or session.status != SessionStatus.RUNNING:
            return False
        
        session.status = SessionStatus.PAUSED
        self._save_session(session)
        return True
    
    def resume_session(self, session_id: str) -> bool:
        """Resume a paused session"""
        session = self.get_session(session_id)
        if not session or session.status != SessionStatus.PAUSED:
            return False
        
        session.status = SessionStatus.RUNNING
        self._save_session(session)
        return True
    
    def cancel_session(self, session_id: str) -> bool:
        """Cancel a session"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        session.status = SessionStatus.CANCELLED
        session.metadata["cancelled_at"] = datetime.now(timezone.utc).isoformat()
        
        self._save_session(session)
        return True
    
    def complete_session(self, session_id: str) -> bool:
        """Mark a session as completed"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        session.status = SessionStatus.COMPLETED
        session.metadata["completed_at"] = datetime.now(timezone.utc).isoformat()
        
        self._save_session(session)
        return True
    
    def add_finding(self, session_id: str, finding: Finding):
        """Add a finding to a session"""
        session = self.get_session(session_id)
        if not session:
            return
        
        session.add_finding(finding)
        self._save_session(session)
    
    def send_message(self, session_id: str, from_agent: str, to_agent: str,
                    message_type: str, content: Dict[str, Any],
                    reply_to: str = None) -> AgentMessage:
        """Send a message between agents"""
        session = self.get_session(session_id)
        if not session:
            return None
        
        message = AgentMessage(
            message_id=str(uuid.uuid4()),
            from_agent=from_agent,
            to_agent=to_agent,
            timestamp=datetime.now(timezone.utc).isoformat(),
            message_type=message_type,
            content=content,
            reply_to=reply_to
        )
        
        session.add_message(message)
        self._save_session(session)
        
        # Trigger message handlers
        self._trigger_message_handlers(session_id, message)
        
        return message
    
    def register_message_handler(self, message_type: str, handler: Callable):
        """Register a handler for specific message types"""
        if message_type not in self.message_handlers:
            self.message_handlers[message_type] = []
        self.message_handlers[message_type].append(handler)
    
    def _trigger_message_handlers(self, session_id: str, message: AgentMessage):
        """Trigger registered message handlers"""
        handlers = self.message_handlers.get(message.message_type, [])
        for handler in handlers:
            try:
                handler(session_id, message)
            except Exception as e:
                print(f"Error in message handler: {e}")
    
    def merge_findings(self, session_id: str) -> List[Finding]:
        """Merge and deduplicate findings from all agents"""
        session = self.get_session(session_id)
        if not session:
            return []
        
        # Deduplicate findings
        seen_keys = set()
        merged_findings = []
        
        for finding in session.findings:
            # Create a unique key for deduplication
            key = (
                finding.finding_type,
                finding.target,
                finding.title[:100],
                finding.severity
            )
            
            if key not in seen_keys:
                seen_keys.add(key)
                merged_findings.append(finding)
        
        return merged_findings
    
    def generate_session_report(self, session_id: str) -> Dict[str, Any]:
        """Generate a comprehensive report for a session"""
        session = self.get_session(session_id)
        if not session:
            return {}
        
        # Merge findings
        merged_findings = self.merge_findings(session_id)
        
        # Count findings by severity
        severity_counts = {}
        for finding in merged_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        # Count findings by type
        type_counts = {}
        for finding in merged_findings:
            type_counts[finding.finding_type] = type_counts.get(finding.finding_type, 0) + 1
        
        # Compile report
        report = {
            "session_id": session.session_id,
            "target": session.target,
            "objective": session.objective,
            "status": session.status.value,
            "created_at": session.created_at,
            "started_at": session.metadata.get("started_at"),
            "completed_at": session.metadata.get("completed_at"),
            "duration_seconds": None,
            "findings": {
                "total": len(merged_findings),
                "by_severity": severity_counts,
                "by_type": type_counts,
                "critical": [f.to_dict() for f in session.get_findings_by_severity("critical")],
                "high": [f.to_dict() for f in session.get_findings_by_severity("high")],
                "medium": [f.to_dict() for f in session.get_findings_by_severity("medium")],
                "low": [f.to_dict() for f in session.get_findings_by_severity("low")],
                "info": [f.to_dict() for f in session.get_findings_by_severity("info")],
                "all": [f.to_dict() for f in merged_findings]
            },
            "agents": session.agents_status,
            "orchestrator_status": session.orchestrator.get_status(),
            "messages": {
                "total": len(session.messages),
                "by_type": {}
            },
            "metadata": session.metadata
        }
        
        # Count messages by type
        for message in session.messages:
            msg_type = message.message_type
            report["messages"]["by_type"][msg_type] = report["messages"]["by_type"].get(msg_type, 0) + 1
        
        # Calculate duration
        if session.metadata.get("completed_at"):
            start = datetime.fromisoformat(session.metadata.get("started_at"))
            end = datetime.fromisoformat(session.metadata.get("completed_at"))
            report["duration_seconds"] = (end - start).total_seconds()
        
        return report
    
    def _save_session(self, session: MultiAgentSession):
        """Persist session to disk"""
        session_file = os.path.join(self.storage_dir, f"{session.session_id}.json")
        
        session_data = {
            "session_id": session.session_id,
            "target": session.target,
            "objective": session.objective,
            "status": session.status.value,
            "created_at": session.created_at,
            "findings": [f.to_dict() for f in session.findings],
            "messages": [
                {
                    "message_id": m.message_id,
                    "from_agent": m.from_agent,
                    "to_agent": m.to_agent,
                    "timestamp": m.timestamp,
                    "message_type": m.message_type,
                    "content": m.content,
                    "reply_to": m.reply_to
                }
                for m in session.messages
            ],
            "agents_status": session.agents_status,
            "metadata": session.metadata
            # Note: orchestrator is not saved as it contains complex objects
        }
        
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
    
    def load_session(self, session_id: str) -> Optional[MultiAgentSession]:
        """Load a session from disk"""
        session_file = os.path.join(self.storage_dir, f"{session_id}.json")
        
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        
        # Recreate session
        orchestrator = AgentOrchestrator()
        session = MultiAgentSession(
            session_id=session_data["session_id"],
            target=session_data["target"],
            objective=session_data["objective"],
            status=SessionStatus(session_data["status"]),
            created_at=session_data["created_at"],
            orchestrator=orchestrator,
            agents_status=session_data.get("agents_status", {}),
            metadata=session_data.get("metadata", {})
        )
        
        # Restore findings
        for finding_data in session_data.get("findings", []):
            session.add_finding(Finding.from_dict(finding_data))
        
        # Restore messages
        for msg_data in session_data.get("messages", []):
            message = AgentMessage(**msg_data)
            session.add_message(message)
        
        self.sessions[session_id] = session
        return session


if __name__ == "__main__":
    # Test multi-agent manager
    manager = MultiAgentManager()
    
    # Create a session
    session = manager.create_session(
        target="192.168.1.0/24",
        objective="Complete security assessment of the network"
    )
    
    print(f"Created session: {session.session_id}")
    
    # Add some test findings
    finding1 = Finding(
        finding_id=str(uuid.uuid4()),
        agent_id="agent_recon",
        task_id="task_1",
        timestamp=datetime.now(timezone.utc).isoformat(),
        finding_type="vulnerability",
        target="192.168.1.100",
        severity="high",
        title="SQL Injection Vulnerability",
        description="SQL injection vulnerability in login.php"
    )
    
    finding2 = Finding(
        finding_id=str(uuid.uuid4()),
        agent_id="agent_creds",
        task_id="task_2",
        timestamp=datetime.now(timezone.utc).isoformat(),
        finding_type="credential",
        target="192.168.1.100",
        severity="critical",
        title="Default Admin Credentials",
        description="Default admin credentials: admin:admin123"
    )
    
    session.add_finding(finding1)
    session.add_finding(finding2)
    
    # Start and complete session
    manager.start_session(session.session_id)
    manager.complete_session(session.session_id)
    
    # Generate report
    report = manager.generate_session_report(session.session_id)
    
    print("\nSession Report:")
    print(json.dumps(report, indent=2, default=str))
