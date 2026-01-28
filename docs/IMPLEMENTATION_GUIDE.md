# Implementation Guide

## Overview

This guide provides step-by-step instructions for implementing each smart feature in TazoSploit. Follow this guide to add capabilities systematically.

## Prerequisites

Before implementing smart features, ensure:

1. Python 3.8+ installed
2. TazoSploit v2 base system running
3. Access to Kali Linux environment
4. Write permissions in `/pentest` directory

---

## Step 1: Skills/Pentest Capabilities System

### 1.1 Create Directory Structure

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
mkdir -p skills/{reconnaissance,sql_injection,xss,privilege_escalation,credential_access,lateral_movement}
```

### 1.2 Implement Core System

**File**: `skills/skill_loader.py`

```python
#!/usr/bin/env python3
# [Full implementation from SKILLS_SYSTEM.md]
# Copy the skill_loader.py file to this location
```

### 1.3 Create Skill Definitions

For each skill directory, create:

**SKILL.md template**:
```markdown
# [Skill Name]

## Overview
[Brief description]

## Methodology
[Step-by-step approach]

## MITRE ATT&CK Mappings
- [Technique IDs]

## Tools Available
- [Tool 1]: [Description]
- [Tool 2]: [Description]

## Evidence Collection
1. [Evidence item 1]
2. [Evidence item 2]

## Success Criteria
- [Criteria 1]
- [Criteria 2]
```

**tools.yaml template**:
```yaml
tool_name:
  description: "Tool description"
  category: "network|exploitation|web|etc."
  install_cmd: "apt-get install -y package"
  verify_cmd: "tool --version"
  examples:
    - "tool example_command"
```

### 1.4 Test Skills System

```python
from skills.skill_loader import SkillLoader

loader = SkillLoader()
print(f"Loaded {len(loader.skills)} skills")

for skill_id, skill in loader.skills.items():
    print(f"- {skill_id}: {len(skill.tools)} tools")
```

### 1.5 Integrate with DynamicAgent

Modify `kali-executor/open-interpreter/dynamic_agent.py`:

```python
from skills.skill_loader import get_skill_loader

class DynamicAgent:
    def __init__(self, ...):
        # ... existing code ...
        
        # Initialize skill loader
        self.skill_loader = get_skill_loader()
        
        # Add skills to system prompt
        skills_prompt = self.skill_loader.format_skills_for_prompt()
        self.SYSTEM_PROMPT_BASE += f"\n\n{skills_prompt}"
```

### 1.6 Verification

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
python3 -c "from skills.skill_loader import SkillLoader; l=SkillLoader(); print(f'OK: {len(l.skills)} skills')"
```

---

## Step 2: Memory System

### 2.1 Create Directory Structure

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
mkdir -p memory/{TARGET_KNOWLEDGE,SESSION_HISTORY}
```

### 2.2 Implement Enhanced Memory Store

**File**: `memory/memory_store.py`

```python
#!/usr/bin/env python3
# [Full implementation from MEMORY_SYSTEM.md]
# Copy the memory_store.py file to this location
```

### 2.3 Initialize Threat Intelligence

```python
from memory.memory_store import initialize_threat_intel
initialize_threat_intel()
```

This creates `memory/THREAT_INTEL.md`.

### 2.4 Test Memory System

```python
from memory.memory_store import EnhancedMemoryStore

store = EnhancedMemoryStore(tenant_id="test", target="test-target")

# Record technique
store.record_technique("T1190", "SQL Injection", success=True)

# Add credential pattern
store.add_credential_pattern("admin:admin123", "weak", "test-target")

# Generate report
report = store.generate_threat_intel_report()
print(report)
```

### 2.5 Integrate with DynamicAgent

Modify `kali-executor/open-interpreter/dynamic_agent.py`:

```python
from memory.memory_store import EnhancedMemoryStore

class DynamicAgent:
    def run(self, target: str, objective: str):
        # ... existing code ...
        
        # Initialize enhanced memory
        self.memory_store = EnhancedMemoryStore(tenant_id=tenant_id, target=target)
        
        # Add memories to initial prompt
        memory_context = self.memory_store.get_target_knowledge()
        if memory_context:
            initial_prompt += f"\n\n**Target Knowledge:**\n{memory_context}\n"
```

### 2.6 Verification

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
python3 -c "from memory.memory_store import EnhancedMemoryStore; s=EnhancedMemoryStore(); print('OK: Memory system working')"
```

---

## Step 3: Multi-Agent Orchestration

### 3.1 Implement Orchestrator

**File**: `orchestrator.py`

```python
#!/usr/bin/env python3
# [Full implementation from MULTI_AGENT_SYSTEM.md]
# Copy the orchestrator.py file to this location
```

### 3.2 Implement Multi-Agent Manager

**File**: `multi_agent.py`

```python
#!/usr/bin/env python3
# [Full implementation from MULTI_AGENT_SYSTEM.md]
# Copy the multi_agent.py file to this location
```

### 3.3 Test Multi-Agent System

```python
import asyncio
from orchestrator import AgentOrchestrator
from multi_agent import MultiAgentManager

async def test():
    # Create orchestrator and manager
    orchestrator = AgentOrchestrator()
    manager = MultiAgentManager()
    
    # Create session
    session = manager.create_session(
        target="192.168.1.100",
        objective="Complete security assessment"
    )
    
    # Create task
    task = orchestrator.create_task(
        description="Scan network",
        target="192.168.1.100",
        skills_required=["reconnaissance"]
    )
    
    # Execute
    result = await orchestrator.execute_task(task)
    print(f"Result: {result.status}")
    
    # Complete session
    manager.start_session(session.session_id)
    manager.complete_session(session.session_id)
    
    # Generate report
    report = manager.generate_session_report(session.session_id)
    print(f"Report: {report['findings']['total']} findings")

asyncio.run(test())
```

### 3.4 Verification

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
python3 -c "from orchestrator import AgentOrchestrator; o=AgentOrchestrator(); print('OK: Orchestrator working')"
python3 -c "from multi_agent import MultiAgentManager; m=MultiAgentManager(); print('OK: Multi-agent manager working')"
```

---

## Step 4: Heartbeat System

### 4.1 Implement Heartbeat System

**File**: `heartbeat.py`

```python
#!/usr/bin/env python3
# [Full implementation from HEARTBEAT_SYSTEM.md]
# Copy the heartbeat.py file to this location
```

### 4.2 Generate Cron Configuration

```bash
python3 heartbeat.py --cron > /tmp/tazosploit_crontab
crontab -l 2>/dev/null | grep -v "TazoSploit" > /tmp/crontab_backup
cat /tmp/tazosploit_crontab >> /tmp/crontab_backup
crontab /tmp/crontab_backup
```

### 4.3 Test Heartbeat System

```python
import asyncio
from heartbeat import HeartbeatSystem, HeartbeatConfig

async def test():
    config = HeartbeatConfig()
    config.notification_channels = ["log"]
    config.scan_networks = ["192.168.1.0/24"]
    
    system = HeartbeatSystem(config)
    
    # Run checks
    await system._run_checks()
    
    # Get alerts
    alerts = system.get_recent_alerts(hours=1)
    print(f"Alerts: {len(alerts)}")

asyncio.run(test())
```

### 4.4 Verification

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
python3 -c "from heartbeat import HeartbeatSystem; print('OK: Heartbeat system working')"
```

---

## Step 5: MCP Integration

### 5.1 Create MCP Tools Directory

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
mkdir -p mcp_tools
```

### 5.2 Implement MCP Integration

**File**: `mcp_integration.py`

```python
#!/usr/bin/env python3
# [Full implementation from MCP_INTEGRATION.md]
# Copy the mcp_integration.py file to this location
```

### 5.3 Create Example MCP Tools

**File**: `mcp_tools/nmap_scan.json`

```json
{
  "name": "nmap_scan",
  "description": "Perform network scanning with nmap",
  "category": "reconnaissance",
  "requires_target": true,
  "input_schema": {
    "type": "object",
    "properties": {
      "network": {"type": "string"}
    },
    "required": ["network"]
  }
}
```

**File**: `mcp_tools/sqlmap_exploit.json`

```json
{
  "name": "sqlmap_exploit",
  "description": "Automated SQL injection exploitation",
  "category": "exploitation",
  "requires_target": true,
  "input_schema": {
    "type": "object",
    "properties": {
      "url": {"type": "string"}
    },
    "required": ["url"]
  }
}
```

### 5.4 Test MCP Integration

```python
import asyncio
from mcp_integration import MCPIntegration

async def test():
    mcp = MCPIntegration()
    
    # List built-in tools
    tools = mcp.get_all_tools()
    print(f"Built-in tools: {len(tools)}")
    for tool in tools:
        print(f"- {tool.name}")
    
    # Test tool call (mock)
    # result = await mcp.call_tool("nmap_scan", {"network": "192.168.1.0/24"})

asyncio.run(test())
```

### 5.5 Verification

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
python3 -c "from mcp_integration import MCPIntegration; m=MCPIntegration(); print(f'OK: MCP working, {len(m.get_all_tools())} tools')"
```

---

## Step 6: Natural Language Interface

### 6.1 Implement NLI

**File**: `nli.py`

```python
#!/usr/bin/env python3
# [Full implementation from NLI_SYSTEM.md]
# Copy the nli.py file to this location
```

### 6.2 Create API Endpoint

**File**: `control-plane/api/routers/nli.py` (new file)

```python
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from nli import NaturalLanguageInterface

router = APIRouter(prefix="/api/v1/nli", tags=["natural-language"])
nli = NaturalLanguageInterface()

class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"

class ChatResponse(BaseModel):
    message: str
    intent: str
    confidence: float
    data: dict = None

@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    response = nli.process_input(request.message)
    return ChatResponse(
        message=response.message,
        intent=response.intent.value,
        confidence=nli.parser._detect_intent(request.message)[1],
        data=response.data
    )
```

### 6.3 Register API Router

**File**: `control-plane/main.py`

```python
from api.routers import nli

# Add to FastAPI app
app.include_router(nli.router)
```

### 6.4 Test NLI

```python
from nli import NaturalLanguageInterface

nli = NaturalLanguageInterface()

# Test parsing
test_queries = [
    "Scan the network 192.168.1.0/24",
    "Test for SQL injection on this URL",
    "What did you find?",
    "Generate a report",
    "Help"
]

for query in test_queries:
    print(f"\nQuery: {query}")
    response = nli.process_input(query)
    print(f"Intent: {response.intent.value}")
    print(f"Message: {response.message[:100]}...")
```

### 6.5 Verification

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
python3 -c "from nli import NaturalLanguageInterface; n=NaturalLanguageInterface(); print('OK: NLI working')"
```

---

## Step 7: Documentation

### 7.1 Create Documentation Files

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit/docs

# Create documentation files
# - SKILLS_SYSTEM.md
# - MEMORY_SYSTEM.md
# - HEARTBEAT_SYSTEM.md
# - MULTI_AGENT_SYSTEM.md
# - NLI_SYSTEM.md
# - MCP_INTEGRATION.md
# - SMART_FEATURES_OVERVIEW.md
# - IMPLEMENTATION_GUIDE.md (this file)
```

### 7.2 Verify Documentation

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit/docs
ls -la *.md
# Should show 8 markdown files
```

---

## Integration Testing

### Test Complete System

```python
#!/usr/bin/env python3
"""
Integration test for all smart features
"""

import asyncio
from skills.skill_loader import SkillLoader
from memory.memory_store import EnhancedMemoryStore
from orchestrator import AgentOrchestrator
from multi_agent import MultiAgentManager
from heartbeat import HeartbeatSystem, HeartbeatConfig
from mcp_integration import MCPIntegration
from nli import NaturalLanguageInterface

async def test_all_features():
    print("=" * 60)
    print("Testing All Smart Features")
    print("=" * 60)
    
    # 1. Skills System
    print("\n1. Skills System")
    skill_loader = SkillLoader()
    print(f"   ✓ Loaded {len(skill_loader.skills)} skills")
    
    # 2. Memory System
    print("\n2. Memory System")
    memory = EnhancedMemoryStore(tenant_id="test", target="test-target")
    memory.record_technique("T1190", "SQL Injection", success=True)
    print(f"   ✓ Memory system working")
    
    # 3. Multi-Agent System
    print("\n3. Multi-Agent System")
    orchestrator = AgentOrchestrator()
    manager = MultiAgentManager()
    session = manager.create_session("test-target", "Test objective")
    print(f"   ✓ Orchestrator and manager working")
    
    # 4. Heartbeat System
    print("\n4. Heartbeat System")
    config = HeartbeatConfig()
    config.notification_channels = ["log"]
    heartbeat = HeartbeatSystem(config)
    print(f"   ✓ Heartbeat system working")
    
    # 5. MCP Integration
    print("\n5. MCP Integration")
    mcp = MCPIntegration()
    print(f"   ✓ MCP working with {len(mcp.get_all_tools())} tools")
    
    # 6. Natural Language Interface
    print("\n6. Natural Language Interface")
    nli = NaturalLanguageInterface()
    response = nli.process_input("Help")
    print(f"   ✓ NLI working (intent: {response.intent.value})")
    
    print("\n" + "=" * 60)
    print("All Features Test Complete!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_all_features())
```

### Run Integration Test

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
python3 test_integration.py
```

---

## Deployment Checklist

- [ ] Skills system implemented and tested
- [ ] Memory system implemented and tested
- [ ] Multi-agent system implemented and tested
- [ ] Heartbeat system implemented and tested
- [ ] MCP integration implemented and tested
- [ ] NLI implemented and tested
- [ ] All documentation created
- [ ] Integration tests passing
- [ ] Unit tests created
- [ ] README.md updated
- [ ] Example scripts created

---

## Creating Unit Tests

### Test Skills System

**File**: `tests/test_skills.py`

```python
import unittest
from skills.skill_loader import SkillLoader

class TestSkills(unittest.TestCase):
    def test_loader_initialization(self):
        loader = SkillLoader()
        self.assertGreater(len(loader.skills), 0)
    
    def test_skill_loading(self):
        loader = SkillLoader()
        skill = loader.get_skill("reconnaissance")
        self.assertIsNotNone(skill)
        self.assertEqual(skill.id, "reconnaissance")

if __name__ == "__main__":
    unittest.main()
```

### Test Memory System

**File**: `tests/test_memory.py`

```python
import unittest
from memory.memory_store import EnhancedMemoryStore

class TestMemory(unittest.TestCase):
    def test_memory_initialization(self):
        memory = EnhancedMemoryStore(tenant_id="test", target="test")
        self.assertIsNotNone(memory)
    
    def test_technique_recording(self):
        memory = EnhancedMemoryStore(tenant_id="test", target="test")
        memory.record_technique("T1190", "SQL Injection", success=True)
        rate = memory.get_technique_success_rate("T1190")
        self.assertEqual(rate, 100.0)

if __name__ == "__main__":
    unittest.main()
```

### Run All Tests

```bash
cd /Users/tazjack/Documents/PenTest/TazoSploit
python3 -m unittest discover tests -v
```

---

## Updating README.md

Add smart features section to `README.md`:

```markdown
## Smart Features

TazoSploit v2 includes AI-driven smart features:

- **Skills System**: Modular pentest capabilities with tool integration
- **Memory System**: Persistent learning across engagements
- **Multi-Agent**: Parallel execution with specialized agents
- **Heartbeat**: Continuous monitoring and alerting
- **MCP Integration**: Dynamic tool registration
- **NLI**: Natural language command interface

See [docs/SMART_FEATURES_OVERVIEW.md](docs/SMART_FEATURES_OVERVIEW.md) for details.
```

---

## Creating Example Scripts

### Example 1: Full Pentest with Smart Features

**File**: `examples/smart_pentest.py`

```python
#!/usr/bin/env python3
"""
Example: Full pentest using all smart features
"""

import asyncio
from skills.skill_loader import SkillLoader
from memory.memory_store import EnhancedMemoryStore
from orchestrator import AgentOrchestrator
from multi_agent import MultiAgentManager

async def smart_pentest():
    # Initialize systems
    skill_loader = SkillLoader()
    memory = EnhancedMemoryStore(tenant_id="example", target="192.168.1.100")
    orchestrator = AgentOrchestrator()
    manager = MultiAgentManager()
    
    # Create session
    session = manager.create_session(
        target="192.168.1.100",
        objective="Complete security assessment"
    )
    
    # Create parallel tasks
    tasks = [
        orchestrator.create_task("Scan network", "192.168.1.100", ["reconnaissance"], priority=10),
        orchestrator.create_task("Test web app", "http://192.168.1.100", ["xss"], priority=8),
        orchestrator.create_task("Check credentials", "192.168.1.100", ["credential_access"], priority=7)
    ]
    
    # Execute in parallel
    results = await orchestrator.execute_parallel(tasks, max_concurrent=3)
    
    # Record findings to memory
    # ... (findings from execution)
    
    # Generate learning recommendations
    recommendations = memory.get_learning_recommendations()
    print("Recommendations:")
    for rec in recommendations:
        print(f"- {rec}")
    
    # Complete session and generate report
    manager.complete_session(session.session_id)
    report = manager.generate_session_report(session.session_id)
    print(f"Report: {report['findings']['total']} findings")

if __name__ == "__main__":
    asyncio.run(smart_pentest())
```

### Example 2: NLI Interaction

**File**: `examples/nli_demo.py`

```python
#!/usr/bin/env python3
"""
Example: Natural language interaction
"""

from nli import NaturalLanguageInterface

def demo_nli():
    nli = NaturalLanguageInterface()
    
    print("TazoSploit Natural Language Interface")
    print("Type 'exit' to quit\n")
    
    while True:
        user_input = input("You: ")
        if user_input.lower() in ['exit', 'quit']:
            break
        
        response = nli.process_input(user_input)
        print(f"\nBot: {response.message}\n")
        
        if response.suggestions:
            print("Suggestions:")
            for suggestion in response.suggestions:
                print(f"- {suggestion}")

if __name__ == "__main__":
    demo_nli()
```

---

## Troubleshooting

### Common Issues

**Issue**: Import errors for new modules

**Solution**: Ensure `PYTHONPATH` includes project root:
```bash
export PYTHONPATH=/Users/tazjack/Documents/PenTest/TazoSploit:$PYTHONPATH
```

**Issue**: Permissions denied on /pentest

**Solution**: Ensure directory exists and is writable:
```bash
sudo mkdir -p /pentest/{memory,sessions}
sudo chown $USER:$USER /pentest/{memory,sessions}
```

**Issue**: Async functions not executing

**Solution**: Always use `asyncio.run()` or event loop:
```python
import asyncio
async def main():
    # your async code
asyncio.run(main())
```

---

## Next Steps

1. **Review Documentation**: Read all smart features documentation
2. **Run Tests**: Execute unit tests and integration tests
3. **Try Examples**: Run example scripts to see features in action
4. **Customize**: Adapt to your specific pentesting needs
5. **Contribute**: Share improvements with the community

---

## Support

For issues or questions:
1. Check relevant documentation file
2. Review troubleshooting section
3. Check existing issues in repository
4. Create new issue with details

---

## Summary

This implementation guide has walked you through:

1. ✓ Skills/Pentest Capabilities System
2. ✓ Persistent Memory & Threat Intelligence
3. ✓ Multi-Agent Orchestration
4. ✓ Proactive Monitoring (Heartbeat)
5. ✓ MCP Server Integration
6. ✓ Natural Language Interface
7. ✓ Documentation

All smart features are now implemented and ready for use. Follow the examples and best practices to get the most out of TazoSploit's AI-driven capabilities.
