#!/usr/bin/env python3
"""
TazoSploit Multi-Agent Orchestrator
Coordinates multiple specialized agents for parallel pentesting execution.

Features:
- Agent spawning for parallel execution
- Specialized agents per skill set
- Agent coordination and result aggregation
- Conflict resolution and deduplication
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json

from skills.skill_loader import SkillLoader, Skill


class AgentStatus(Enum):
    """Agent execution status"""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AgentTask:
    """Represents a task assigned to an agent"""
    task_id: str
    description: str
    target: str
    skills_required: List[str]
    priority: int = 5  # 1-10, 10 is highest
    dependencies: List[str] = field(default_factory=list)
    timeout: int = 600
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Represents result from an agent"""
    task_id: str
    agent_id: str
    status: AgentStatus
    findings: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    error: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Agent:
    """Represents a specialized agent"""
    agent_id: str
    name: str
    skills: List[str]  # Skill IDs this agent is good at
    status: AgentStatus = AgentStatus.IDLE
    current_task: Optional[AgentTask] = None
    capabilities: Dict[str, Any] = field(default_factory=dict)
    last_activity: str = None


class AgentOrchestrator:
    """
    Orchestrates multiple specialized agents for parallel pentesting.
    Manages agent lifecycle, task assignment, and result aggregation.
    """
    
    def __init__(self, skill_loader: SkillLoader = None):
        self.skill_loader = skill_loader or SkillLoader()
        self.agents: Dict[str, Agent] = {}
        self.tasks: Dict[str, AgentTask] = {}
        self.results: Dict[str, AgentResult] = {}
        self.task_queue: List[AgentTask] = []
        
        # Initialize specialized agents
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize default set of specialized agents based on skills"""
        # Create agents for each skill category
        skills = self.skill_loader.get_all_skills()
        
        # Reconnaissance agent
        if any(s.id == "reconnaissance" for s in skills):
            self._spawn_agent(
                agent_id="agent_recon",
                name="Reconnaissance Specialist",
                skills=["reconnaissance"],
                capabilities={"speed": "high", "stealth": "medium"}
            )
        
        # Exploitation agent
        if any(s.id in ["sql_injection", "xss"] for s in skills):
            self._spawn_agent(
                agent_id="agent_exploit",
                name="Exploitation Specialist",
                skills=["sql_injection", "xss", "privilege_escalation"],
                capabilities={"success_rate": "high", "persistence": "low"}
            )
        
        # Credential/Access agent
        if any(s.id == "credential_access" for s in skills):
            self._spawn_agent(
                agent_id="agent_creds",
                name="Credential Access Specialist",
                skills=["credential_access", "lateral_movement"],
                capabilities={"stealth": "high", "persistence": "high"}
            )
        
        # General-purpose agent
        self._spawn_agent(
            agent_id="agent_general",
            name="General Pentest Agent",
            skills=[s.id for s in skills],
            capabilities={"flexibility": "high", "knowledge": "high"}
        )
    
    def _spawn_agent(self, agent_id: str, name: str, skills: List[str], 
                    capabilities: Dict[str, Any] = None):
        """Spawn a new specialized agent"""
        agent = Agent(
            agent_id=agent_id,
            name=name,
            skills=skills,
            capabilities=capabilities or {}
        )
        self.agents[agent_id] = agent
        return agent
    
    def add_agent(self, agent_id: str, name: str, skills: List[str],
                  capabilities: Dict[str, Any] = None):
        """Add a custom agent to the pool"""
        return self._spawn_agent(agent_id, name, skills, capabilities)
    
    def create_task(self, description: str, target: str, skills_required: List[str],
                   priority: int = 5, dependencies: List[str] = None,
                   timeout: int = 600, metadata: Dict[str, Any] = None) -> AgentTask:
        """Create a new task for assignment"""
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            description=description,
            target=target,
            skills_required=skills_required,
            priority=priority,
            dependencies=dependencies or [],
            timeout=timeout,
            metadata=metadata or {}
        )
        self.tasks[task.task_id] = task
        return task
    
    def assign_task(self, task: AgentTask) -> Optional[Agent]:
        """Assign a task to the most suitable available agent"""
        # Filter available agents
        available_agents = [
            a for a in self.agents.values() 
            if a.status == AgentStatus.IDLE
        ]
        
        if not available_agents:
            return None
        
        # Score agents based on skill match and capabilities
        scored_agents = []
        for agent in available_agents:
            score = self._score_agent_for_task(agent, task)
            if score > 0:
                scored_agents.append((score, agent))
        
        if not scored_agents:
            return None
        
        # Sort by score (descending) and select best
        scored_agents.sort(key=lambda x: x[0], reverse=True)
        best_agent = scored_agents[0][1]
        
        # Assign task
        best_agent.status = AgentStatus.RUNNING
        best_agent.current_task = task
        best_agent.last_activity = datetime.now(timezone.utc).isoformat()
        
        return best_agent
    
    def _score_agent_for_task(self, agent: Agent, task: AgentTask) -> float:
        """Score an agent's suitability for a task"""
        score = 0.0
        
        # Skill matching (most important)
        required_skills = set(task.skills_required)
        agent_skills = set(agent.skills)
        
        skill_match_ratio = len(required_skills & agent_skills) / len(required_skills)
        score += skill_match_ratio * 70  # 70% weight on skills
        
        # Priority consideration
        score += task.priority * 2  # Up to 20 points for priority
        
        # Bonus if agent specializes in these skills
        if len(agent.skills) <= 3 and required_skills.issubset(agent_skills):
            score += 10  # Specialization bonus
        
        return score
    
    async def execute_task(self, task: AgentTask, agent: Agent = None) -> AgentResult:
        """Execute a task (placeholder - actual execution depends on DynamicAgent)"""
        if agent is None:
            agent = self.assign_task(task)
            if agent is None:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id="none",
                    status=AgentStatus.FAILED,
                    error="No available agent to execute task"
                )
        
        # Placeholder execution - in real implementation, this would:
        # 1. Configure DynamicAgent with required skills
        # 2. Execute the pentest against target
        # 3. Collect results and artifacts
        
        # Simulate execution time
        await asyncio.sleep(0.1)
        
        result = AgentResult(
            task_id=task.task_id,
            agent_id=agent.agent_id,
            status=AgentStatus.COMPLETED,
            findings=[],
            artifacts=[],
            execution_time=0.1,
            metrics={}
        )
        
        # Update agent status
        agent.status = AgentStatus.IDLE
        agent.current_task = None
        agent.last_activity = datetime.now(timezone.utc).isoformat()
        
        self.results[task.task_id] = result
        return result
    
    async def execute_parallel(self, tasks: List[AgentTask], max_concurrent: int = 3) -> List[AgentResult]:
        """Execute multiple tasks in parallel with concurrency limit"""
        results = []
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_with_semaphore(task: AgentTask):
            async with semaphore:
                return await self.execute_task(task)
        
        # Execute all tasks
        results = await asyncio.gather(
            *[execute_with_semaphore(task) for task in tasks],
            return_exceptions=True
        )
        
        return results
    
    def get_task_dependencies(self, task_id: str) -> List[AgentResult]:
        """Get results for all tasks that this task depends on"""
        task = self.tasks.get(task_id)
        if not task:
            return []
        
        return [
            self.results[dep_id] 
            for dep_id in task.dependencies 
            if dep_id in self.results
        ]
    
    def aggregate_results(self, task_ids: List[str] = None) -> Dict[str, Any]:
        """Aggregate results from multiple tasks into a consolidated report"""
        if task_ids is None:
            task_ids = list(self.results.keys())
        
        aggregated = {
            "total_tasks": len(task_ids),
            "successful_tasks": 0,
            "failed_tasks": 0,
            "all_findings": [],
            "all_artifacts": [],
            "execution_metrics": {
                "total_time": 0.0,
                "agent_usage": {}
            },
            "summary": {}
        }
        
        for task_id in task_ids:
            result = self.results.get(task_id)
            if not result:
                continue
            
            if result.status == AgentStatus.COMPLETED:
                aggregated["successful_tasks"] += 1
            else:
                aggregated["failed_tasks"] += 1
            
            aggregated["all_findings"].extend(result.findings)
            aggregated["all_artifacts"].extend(result.artifacts)
            aggregated["execution_metrics"]["total_time"] += result.execution_time
            
            # Track agent usage
            if result.agent_id not in aggregated["execution_metrics"]["agent_usage"]:
                aggregated["execution_metrics"]["agent_usage"][result.agent_id] = 0
            aggregated["execution_metrics"]["agent_usage"][result.agent_id] += 1
        
        # Deduplicate findings
        aggregated["all_findings"] = self._deduplicate_findings(aggregated["all_findings"])
        
        return aggregated
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on key attributes"""
        seen = set()
        deduplicated = []
        
        for finding in findings:
            # Create a key from finding attributes
            key = (
                finding.get("type"),
                finding.get("target"),
                finding.get("severity"),
                finding.get("description", "")[:100]
            )
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
        
        return deduplicated
    
    def get_status(self) -> Dict[str, Any]:
        """Get overall orchestrator status"""
        return {
            "total_agents": len(self.agents),
            "agents_idle": len([a for a in self.agents.values() if a.status == AgentStatus.IDLE]),
            "agents_running": len([a for a in self.agents.values() if a.status == AgentStatus.RUNNING]),
            "total_tasks": len(self.tasks),
            "tasks_completed": len(self.results),
            "task_queue_size": len(self.task_queue)
        }


if __name__ == "__main__":
    # Test orchestrator
    async def test_orchestrator():
        orchestrator = AgentOrchestrator()
        
        # Create tasks
        task1 = orchestrator.create_task(
            description="Scan network for open ports",
            target="192.168.1.0/24",
            skills_required=["reconnaissance"],
            priority=10
        )
        
        task2 = orchestrator.create_task(
            description="Test web application for SQL injection",
            target="http://192.168.1.100",
            skills_required=["sql_injection"],
            priority=8
        )
        
        task3 = orchestrator.create_task(
            description="Extract credentials from compromised system",
            target="192.168.1.100",
            skills_required=["credential_access"],
            priority=7,
            dependencies=[task2.task_id]  # Depends on successful exploitation
        )
        
        # Execute tasks in parallel (task3 will wait for task2)
        results = await orchestrator.execute_parallel([task1, task2], max_concurrent=2)
        
        # Print results
        for result in results:
            print(f"Task {result.task_id}: {result.status}")
        
        # Get status
        print("\nOrchestrator Status:")
        print(json.dumps(orchestrator.get_status(), indent=2))
    
    asyncio.run(test_orchestrator())
