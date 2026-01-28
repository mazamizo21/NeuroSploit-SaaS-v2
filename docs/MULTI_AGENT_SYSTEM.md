# Multi-Agent System Documentation

## Overview

The TazoSploit Multi-Agent System enables parallel execution of specialized agents for comprehensive pentesting. Agents can work simultaneously on different aspects of a target, coordinating through an orchestrator to maximize efficiency.

## Architecture

```
orchestrator.py              # Agent orchestration and coordination
├── AgentOrchestrator       # Main orchestration engine
├── Agent                   # Specialized agent representation
├── AgentTask               # Task definition
├── AgentResult             # Execution result
└── AgentStatus             # Agent execution state

multi_agent.py              # Multi-agent session management
├── MultiAgentManager       # Session lifecycle management
├── MultiAgentSession      # Active session representation
├── Finding               # Security finding data structure
├── AgentMessage          # Inter-agent communication
└── SessionStatus        # Session state
```

## Core Components

### AgentOrchestrator

Manages agent pool, task assignment, and execution coordination:

```python
from orchestrator import AgentOrchestrator

orchestrator = AgentOrchestrator()

# Create a task
task = orchestrator.create_task(
    description="Scan network for open ports",
    target="192.168.1.0/24",
    skills_required=["reconnaissance"],
    priority=10
)

# Assign task to best agent
agent = orchestrator.assign_task(task)

# Execute task
result = await orchestrator.execute_task(task, agent)

# Execute multiple tasks in parallel
results = await orchestrator.execute_parallel([task1, task2, task3], max_concurrent=3)

# Aggregate results
aggregated = orchestrator.aggregate_results([task1.task_id, task2.task_id])
```

### MultiAgentManager

Manages multi-agent sessions with communication and finding management:

```python
from multi_agent import MultiAgentManager, Finding

manager = MultiAgentManager()

# Create a session
session = manager.create_session(
    target="192.168.1.0/24",
    objective="Complete security assessment"
)

# Add findings
finding = Finding(
    finding_id=str(uuid.uuid4()),
    agent_id="agent_recon",
    task_id="task_1",
    timestamp=datetime.now(timezone.utc).isoformat(),
    finding_type="vulnerability",
    target="192.168.1.100",
    severity="high",
    title="SQL Injection Vulnerability",
    description="SQL injection in login.php",
    mitre_techniques=["T1190"]
)
session.add_finding(finding)

# Start and complete session
manager.start_session(session.session_id)
manager.complete_session(session.session_id)

# Generate report
report = manager.generate_session_report(session.session_id)
```

## Specialized Agents

The system automatically creates specialized agents based on available skills:

### 1. Reconnaissance Agent
- **ID**: `agent_recon`
- **Skills**: reconnaissance
- **Capabilities**: High speed, medium stealth
- **Best for**: Network discovery, port scanning, service enumeration

### 2. Exploitation Agent
- **ID**: `agent_exploit`
- **Skills**: sql_injection, xss, privilege_escalation
- **Capabilities**: High success rate, low persistence
- **Best for**: Vulnerability exploitation, RCE

### 3. Credential/Access Agent
- **ID**: `agent_creds`
- **Skills**: credential_access, lateral_movement
- **Capabilities**: High stealth, high persistence
- **Best for**: Credential extraction, moving laterally

### 4. General-Purpose Agent
- **ID**: `agent_general`
- **Skills**: All available skills
- **Capabilities**: High flexibility, high knowledge
- **Best for**: General tasks, unknown attack vectors

## Task Assignment

The orchestrator uses intelligent scoring to assign tasks to the most suitable agent:

```python
def _score_agent_for_task(agent: Agent, task: AgentTask) -> float:
    """
    Score = (skill_match_ratio * 0.7) + (priority * 0.2) + (specialization_bonus * 0.1)
    
    - Skill match ratio: How many required skills does agent have?
    - Priority: Higher priority tasks score higher
    - Specialization bonus: Bonus for agents with few skills (specialized)
    """
```

### Assignment Process

1. **Filter available agents**: Only agents with `status == IDLE`
2. **Score each agent**: Calculate suitability score
3. **Select best agent**: Highest score wins
4. **Assign task**: Mark agent as RUNNING with task
5. **Execute task**: Agent performs the work
6. **Update status**: Mark agent as IDLE, store result

## Parallel Execution

Execute multiple tasks simultaneously with concurrency limits:

```python
# Create multiple tasks
tasks = [
    orchestrator.create_task("Scan network", target, ["reconnaissance"], priority=10),
    orchestrator.create_task("Test for SQLi", url, ["sql_injection"], priority=8),
    orchestrator.create_task("Extract credentials", host, ["credential_access"], priority=7, dependencies=[sql_task.task_id])
]

# Execute in parallel (max 3 concurrent)
results = await orchestrator.execute_parallel(tasks, max_concurrent=3)

# Task 3 will wait for task 2 to complete due to dependency
```

## Inter-Agent Communication

Agents can communicate through the session messaging system:

```python
# Send message from one agent to another
manager.send_message(
    session_id=session.session_id,
    from_agent="agent_recon",
    to_agent="agent_exploit",
    message_type="finding",
    content={
        "type": "vulnerability",
        "target": "192.168.1.100",
        "severity": "high",
        "description": "SQL injection in login.php"
    }
)

# Register message handler
def handle_finding(session_id: str, message: AgentMessage):
    # Process finding
    pass

manager.register_message_handler("finding", handle_finding)
```

## Finding Management

Findings from all agents are collected and deduplicated:

```python
# Add finding to session
session.add_finding(finding)

# Get findings by severity
critical = session.get_findings_by_severity("critical")

# Get findings by type
vulns = session.get_findings_by_type("vulnerability")

# Get findings by agent
agent_findings = session.get_findings_by_agent("agent_recon")

# Merge and deduplicate findings from all agents
merged = manager.merge_findings(session.session_id)
```

### Finding Structure

```python
@dataclass
class Finding:
    finding_id: str
    agent_id: str           # Which agent found it
    task_id: str            # Which task found it
    timestamp: str          # When it was found
    finding_type: str        # vulnerability, credential, misconfig, etc.
    target: str             # Target system
    severity: str           # critical, high, medium, low, info
    title: str             # Finding title
    description: str       # Detailed description
    evidence: List[str]     # Proof of vulnerability
    references: List[str]   # External references
    mitre_techniques: List[str]  # MITRE ATT&CK mappings
    metadata: Dict[str, Any]  # Additional data
```

## Session Lifecycle

### 1. Create Session
```python
session = manager.create_session(target, objective)
# Status: INITIALIZING
```

### 2. Start Session
```python
manager.start_session(session.session_id)
# Status: RUNNING
# Metadata: started_at = timestamp
```

### 3. Add Findings and Messages
```python
session.add_finding(finding)
session.add_message(message)
```

### 4. Complete Session
```python
manager.complete_session(session.session_id)
# Status: COMPLETED
# Metadata: completed_at = timestamp
```

### 5. Generate Report
```python
report = manager.generate_session_report(session.session_id)
# Includes: findings summary, severity breakdown, agent usage, metrics
```

## Report Generation

Comprehensive session reports include:

```python
{
    "session_id": "uuid",
    "target": "192.168.1.0/24",
    "objective": "Complete security assessment",
    "status": "completed",
    "created_at": "2024-01-28T10:00:00Z",
    "started_at": "2024-01-28T10:01:00Z",
    "completed_at": "2024-01-28T12:00:00Z",
    "duration_seconds": 6540,
    "findings": {
        "total": 15,
        "by_severity": {"critical": 2, "high": 5, "medium": 5, "low": 3},
        "by_type": {"vulnerability": 10, "credential": 3, "misconfig": 2},
        "critical": [...],  # List of critical findings
        "high": [...],      # List of high findings
        "all": [...]       # All findings (deduplicated)
    },
    "agents": {
        "agent_recon": "completed",
        "agent_exploit": "completed",
        "agent_creds": "completed"
    },
    "orchestrator_status": {
        "total_agents": 4,
        "agents_idle": 4,
        "agents_running": 0,
        "total_tasks": 3,
        "tasks_completed": 3
    },
    "metadata": {...}
}
```

## API Reference

### AgentOrchestrator

```python
class AgentOrchestrator:
    def __init__(self, skill_loader: SkillLoader = None)
    def add_agent(self, agent_id: str, name: str, skills: List[str], 
                  capabilities: Dict[str, Any] = None)
    def create_task(self, description: str, target: str, skills_required: List[str],
                   priority: int = 5, dependencies: List[str] = None,
                   timeout: int = 600, metadata: Dict[str, Any] = None) -> AgentTask
    def assign_task(self, task: AgentTask) -> Optional[Agent]
    async def execute_task(self, task: AgentTask, agent: Agent = None) -> AgentResult
    async def execute_parallel(self, tasks: List[AgentTask], 
                             max_concurrent: int = 3) -> List[AgentResult]
    def aggregate_results(self, task_ids: List[str] = None) -> Dict[str, Any]
    def get_status(self) -> Dict[str, Any]
```

### MultiAgentManager

```python
class MultiAgentManager:
    def __init__(self, storage_dir: str = "/pentest/sessions")
    def create_session(self, target: str, objective: str, 
                      skills: List[str] = None) -> MultiAgentSession
    def get_session(self, session_id: str) -> Optional[MultiAgentSession]
    def get_all_sessions(self) -> List[MultiAgentSession]
    def start_session(self, session_id: str) -> bool
    def pause_session(self, session_id: str) -> bool
    def resume_session(self, session_id: str) -> bool
    def cancel_session(self, session_id: str) -> bool
    def complete_session(self, session_id: str) -> bool
    def add_finding(self, session_id: str, finding: Finding)
    def send_message(self, session_id: str, from_agent: str, to_agent: str,
                    message_type: str, content: Dict[str, Any],
                    reply_to: str = None) -> AgentMessage
    def register_message_handler(self, message_type: str, handler: Callable)
    def merge_findings(self, session_id: str) -> List[Finding]
    def generate_session_report(self, session_id: str) -> Dict[str, Any]
```

## Examples

### Example 1: Basic Multi-Agent Session

```python
import asyncio
from orchestrator import AgentOrchestrator
from multi_agent import MultiAgentManager

async def main():
    # Create orchestrator and manager
    orchestrator = AgentOrchestrator()
    manager = MultiAgentManager()
    
    # Create session
    session = manager.create_session(
        target="192.168.1.100",
        objective="Complete security assessment"
    )
    
    # Create tasks
    task1 = orchestrator.create_task(
        description="Scan for open ports",
        target="192.168.1.100",
        skills_required=["reconnaissance"],
        priority=10
    )
    
    task2 = orchestrator.create_task(
        description="Test for SQL injection",
        target="http://192.168.1.100/login.php",
        skills_required=["sql_injection"],
        priority=8
    )
    
    # Execute in parallel
    results = await orchestrator.execute_parallel([task1, task2], max_concurrent=2)
    
    # Complete session
    manager.start_session(session.session_id)
    manager.complete_session(session.session_id)
    
    # Generate report
    report = manager.generate_session_report(session.session_id)
    print(report)

asyncio.run(main())
```

### Example 2: Agent Communication

```python
# Register message handler
def on_vulnerability_found(session_id: str, message: AgentMessage):
    finding = Finding(
        finding_id=str(uuid.uuid4()),
        agent_id=message.from_agent,
        task_id=message.content.get("task_id"),
        timestamp=datetime.now(timezone.utc).isoformat(),
        finding_type="vulnerability",
        target=message.content.get("target"),
        severity=message.content.get("severity"),
        title=message.content.get("title"),
        description=message.content.get("description"),
        mitre_techniques=message.content.get("mitre_techniques", [])
    )
    manager.add_finding(session_id, finding)

manager.register_message_handler("vulnerability", on_vulnerability_found)

# Agent sends message
manager.send_message(
    session_id=session.session_id,
    from_agent="agent_exploit",
    to_agent="agent_recon",
    message_type="vulnerability",
    content={
        "target": "192.168.1.100",
        "severity": "high",
        "title": "SQL Injection",
        "description": "SQL injection in login.php",
        "mitre_techniques": ["T1190"]
    }
)
```

### Example 3: Custom Agent

```python
# Add custom agent
orchestrator.add_agent(
    agent_id="agent_custom",
    name="Custom Specialist",
    skills=["web_scanning", "api_testing"],
    capabilities={
        "specialization": "web_apps",
        "custom_tools": ["custom_scanner"]
    }
)

# Create task for custom agent
task = orchestrator.create_task(
    description="Scan web application",
    target="http://example.com",
    skills_required=["web_scanning"],
    priority=9
)

# Assign to custom agent
agent = orchestrator.assign_task(task)
print(f"Assigned to: {agent.name}")
```

## Best Practices

1. **Use Parallel Execution**: Maximize efficiency by running tasks concurrently.
2. **Define Dependencies**: Specify task dependencies when needed.
3. **Prioritize Tasks**: Use priority levels (1-10) to guide execution order.
4. **Specialize Agents**: Create specialized agents for specific domains.
5. **Deduplicate Findings**: Use merge_findings to avoid duplicates.
6. **Generate Reports**: Create comprehensive session reports for documentation.

## Troubleshooting

### Tasks Not Executing

**Problem**: Tasks remain in queue without execution.

**Solution**:
1. Check that agents are available (status == IDLE)
2. Verify task skills match agent capabilities
3. Ensure no circular dependencies in tasks
4. Review orchestrator status for errors

### Findings Not Merging

**Problem**: Duplicate findings appear in reports.

**Solution**:
1. Check that findings have consistent data (type, target, title)
2. Ensure merge_findings is called before report generation
3. Verify finding IDs are unique

### Agent Communication Failing

**Problem**: Messages between agents aren't being delivered.

**Solution**:
1. Ensure message handlers are registered
2. Check session_id is correct in send_message
3. Verify to_agent ID exists in agent pool

## Integration with Skills System

Multi-agent system integrates with Skills System for agent capabilities:

```python
from skills.skill_loader import SkillLoader

# Load skills
skill_loader = SkillLoader()

# Create orchestrator with skill loader
orchestrator = AgentOrchestrator(skill_loader=skill_loader)

# Agents are created based on available skills
# Each agent is assigned relevant skills from skill_loader
```

## Future Enhancements

- Dynamic agent spawning based on workload
- Agent learning from past executions
- Autonomous agent negotiation for task assignment
- Distributed agent execution across multiple hosts
- Agent marketplace for community-contributed agents
- Real-time visualization of agent activity
