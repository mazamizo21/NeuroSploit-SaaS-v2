# TazoSploit — RedAmon Feature Integration Plan

**Date:** 2026-02-15
**Status:** PLANNING
**Priority:** HIGH — competitive parity + differentiation

---

## Overview

Mirror RedAmon's best architectural features while keeping TazoSploit's superior exploitation engine intact. Four major features:

1. Neo4j Knowledge Graph
2. Structured ReAct Agent Output
3. Real-Time Chat + Mid-Run Guidance
4. Human-in-the-Loop Approval Gates

---

## Feature 1: Neo4j Knowledge Graph

### What RedAmon Does
- 17 node types, 20+ relationship types in Neo4j
- Agent queries graph via text-to-Cypher before every attack decision
- Recon data flows in → agent reasons about relationships → exploit results flow back
- Multi-tenant isolation via `user_id`/`project_id` on every node

### What We Need

#### 1.1 Add Neo4j to Docker Compose
```yaml
neo4j:
  image: neo4j:5-community
  environment:
    NEO4J_AUTH: neo4j/${NEO4J_PASSWORD:-tazosploit}
    NEO4J_PLUGINS: '["apoc"]'
  ports:
    - "7474:7474"  # Browser
    - "7687:7687"  # Bolt
  volumes:
    - neo4j_data:/data
```

#### 1.2 Graph Schema (adapted from RedAmon + our data model)
```
Node Types:
  - Target (ip, hostname, os, status)
  - Port (number, protocol, state, service_name)
  - Service (name, version, banner, product)
  - Technology (name, version, categories)
  - Vulnerability (id, name, severity, type, cvss, proven)
  - Credential (username, password_hash, source, cracked)
  - Exploit (attack_type, module, payload, session_id, evidence)
  - Artifact (type: jwt|api_key|cookie|connection_string, value)
  - Skill (name, mitre_ids, phase, category)
  - Finding (title, severity, description, proof_command)

Relationships:
  - (Target)-[:HAS_PORT]->(Port)
  - (Port)-[:RUNS_SERVICE]->(Service)
  - (Service)-[:USES_TECHNOLOGY]->(Technology)
  - (Target)-[:HAS_VULNERABILITY]->(Vulnerability)
  - (Vulnerability)-[:ON_PORT]->(Port)
  - (Vulnerability)-[:EXPLOITED_BY]->(Exploit)
  - (Exploit)-[:TARGETED]->(Target)
  - (Exploit)-[:VIA_PORT]->(Port)
  - (Exploit)-[:YIELDED_CREDENTIAL]->(Credential)
  - (Exploit)-[:YIELDED_ARTIFACT]->(Artifact)
  - (Vulnerability)-[:ADDRESSABLE_BY]->(Skill)
  - (Credential)-[:FOUND_ON]->(Target)
```

#### 1.3 Graph Population Points
- **Recon phase:** nmap/masscan results → Target + Port + Service nodes
- **Vuln scan phase:** Nuclei/custom detections → Vulnerability nodes linked to ports
- **During execution:** Every `_track_vuln_found()` → MERGE Vulnerability node
- **Evidence detection:** Every `_mark_vuln_proven()` → Create Exploit node
- **Artifact extraction:** Every credential/token/key → Credential/Artifact nodes

#### 1.4 Agent Graph Queries
Add a `query_graph` capability to the dynamic agent:
```python
# In dynamic_agent.py — new tool type alongside bash/python
if exec_type == "cypher":
    result = self.neo4j_client.query(content)
    # OR: text-to-cypher via LLM
    cypher = self._generate_cypher(natural_language_query)
    result = self.neo4j_client.query(cypher)
```

Agent can ask:
- "What unproven vulnerabilities exist on this target?"
- "What credentials have I found that I haven't tried on other services?"
- "What ports are running services I haven't scanned yet?"

#### 1.5 Files to Modify
- `docker-compose.yml` — add neo4j service
- `dynamic_agent.py` — add graph query tool, graph population hooks
- NEW: `graph/neo4j_client.py` — connection, query, schema management
- NEW: `graph/schema.py` — node/relationship type definitions
- NEW: `graph/population.py` — functions to populate graph from agent data
- `worker/main.py` — pass Neo4j connection to agent

#### 1.6 Estimated Effort: 2-3 days

---

## Feature 2: Structured ReAct Agent Output

### What RedAmon Does
- Agent outputs structured JSON every iteration: `{ thought, action, tool, reasoning, todo_update }`
- Full execution trace stored and formatted into prompt each iteration
- LLM parse retry (up to 3 attempts with error feedback)
- Auditable reasoning chain

### What We Need

#### 2.1 Structured Output Schema
```python
class AgentStep(BaseModel):
    thought: str          # What am I thinking/reasoning about?
    action: str           # "execute" | "query_graph" | "report_finding" | "request_guidance"
    tool: str             # "bash" | "python" | "cypher" | "metasploit"
    command: str          # The actual command to execute
    reasoning: str        # Why this command? What do I expect?
    target_vuln: str      # Which vulnerability am I working on? (links to tracker)
    confidence: float     # 0-1 how confident am I this will work?
    todo_update: list     # Tasks completed / tasks added
```

#### 2.2 Parse with Retry
```python
for attempt in range(3):
    response = self._query_llm(prompt)
    try:
        step = AgentStep.model_validate_json(response)
        break
    except ValidationError as e:
        prompt += f"\n\nYour previous response was invalid JSON: {e}. Try again."
```

#### 2.3 Execution Trace
- Store every `AgentStep` in `self.execution_trace[]`
- Format last N steps into system prompt (sliding window)
- Persist trace to disk alongside existing state files
- This replaces raw conversation history for decision-making context

#### 2.4 Benefits for TazoSploit
- **Vuln tracker integration:** `target_vuln` field links every action to a specific vulnerability
- **Confidence scoring:** Low confidence actions can trigger supervisor review
- **Auditable reports:** Every step has reasoning — great for pentest reports
- **Better stall detection:** Supervisor can analyze `thought` field for repetitive reasoning

#### 2.5 Files to Modify
- `dynamic_agent.py` — restructure LLM query/response to use structured output
- `supervisor/main.py` — analyze structured trace instead of raw logs
- NEW: `agent/schemas.py` — Pydantic models for agent steps

#### 2.6 Estimated Effort: 1-2 days

---

## Feature 3: Real-Time Chat + Mid-Run Guidance

### What RedAmon Does
- WebSocket chat interface in the webapp
- User can send guidance messages while agent is working
- Agent can ask questions back to user (text, single choice, multi choice)
- Guidance injected into system prompt before next reasoning step
- Not just IP — user provides initial objectives, focus areas, constraints

### What We Need

#### 3.1 Enhanced Job Creation (Not Just IP)
Current flow:
```
User → POST /api/v1/jobs { targets: ["192.168.4.125"], phase: "FULL" }
```

New flow:
```
User → POST /api/v1/jobs {
  targets: ["192.168.4.125"],
  phase: "FULL",
  objectives: [
    "Focus on web application vulnerabilities first",
    "Try to get domain admin credentials",
    "Check for lateral movement opportunities to 192.168.4.0/24 subnet"
  ],
  constraints: [
    "Don't run DoS attacks",
    "Avoid brute force on Active Directory — lockout policy is 5 attempts"
  ],
  priority_services: ["http", "smb", "rdp"],
  initial_intel: "Windows 11 Pro, joined to CORP.LOCAL domain, runs IIS 10"
}
```

#### 3.2 WebSocket Chat Endpoint
```python
# NEW: api/websocket.py
@app.websocket("/api/v1/jobs/{job_id}/chat")
async def job_chat(websocket, job_id):
    # Bidirectional communication:
    # User → Agent: guidance messages, answers to questions
    # Agent → User: thinking process, tool outputs, questions, findings
```

Message types:
```python
# User → Agent
{ "type": "guidance", "message": "Focus on SMB, I think there's EternalBlue" }
{ "type": "answer", "question_id": "q1", "value": "yes, try it" }
{ "type": "approve", "transition_id": "t1", "decision": "approve" }

# Agent → User
{ "type": "thinking", "thought": "Found open SMB port, checking for MS17-010..." }
{ "type": "tool_output", "tool": "nmap", "output": "445/tcp open microsoft-ds" }
{ "type": "finding", "vuln": { "name": "EternalBlue", "severity": "critical" } }
{ "type": "question", "id": "q1", "text": "Found domain creds. Try pass-the-hash on other hosts?", "options": ["yes", "no", "skip for now"] }
{ "type": "phase_transition", "id": "t1", "from": "recon", "to": "exploitation", "reason": "..." }
```

#### 3.3 Guidance Queue in Dynamic Agent
```python
# In dynamic_agent.py
class DynamicAgent:
    def __init__(self):
        self.guidance_queue = asyncio.Queue()
        self.pending_questions = {}

    async def _check_guidance(self):
        """Called before every LLM query"""
        messages = []
        while not self.guidance_queue.empty():
            msg = self.guidance_queue.get_nowait()
            messages.append(msg)
        if messages:
            self._inject_guidance(messages)  # Add to system prompt

    def _inject_guidance(self, messages):
        guidance_text = "\n".join([
            f"[USER GUIDANCE]: {m['message']}" for m in messages
        ])
        self.system_prompt_additions.append(guidance_text)
```

#### 3.4 Frontend Chat Component
- Real-time chat panel in job detail page (right sidebar)
- Shows agent thinking, tool outputs, findings as they happen
- Input box for guidance messages
- Approval buttons for phase transitions
- Question cards with response options

#### 3.5 Files to Modify
- `control-plane/api/` — add WebSocket endpoint
- `dynamic_agent.py` — add guidance queue, question system, streaming output
- `worker/main.py` — bridge Redis pubsub ↔ WebSocket
- `frontend/` — new ChatPanel component, job detail page redesign
- API schema: enhance `JobCreate` with objectives/constraints/intel fields

#### 3.6 Estimated Effort: 3-4 days

---

## Feature 4: Human-in-the-Loop Approval Gates

### What RedAmon Does
- Phase transitions require user approval (configurable)
- Three options: approve, modify (with feedback), abort
- Auto-approve for safe downgrades (exploitation → informational)
- Approval state persists across WebSocket reconnects

### What We Need

#### 4.1 Approval Gate Configuration
```python
# Per-job settings (in JobCreate schema)
{
    "approval_gates": {
        "recon_to_exploit": true,       # Approve before exploitation attempts
        "exploit_to_post_exploit": true, # Approve before post-exploitation
        "lateral_movement": true,        # Approve before pivoting to new hosts
        "data_exfiltration": true,       # Approve before extracting sensitive data
        "persistence": false             # Auto-approve persistence (lab mode)
    },
    "auto_approve_timeout_seconds": 300  # Auto-approve after 5 min if no response
}
```

#### 4.2 Approval Flow
```
Agent detects phase transition needed
  → Publishes approval request to Redis channel
  → Worker forwards to WebSocket
  → Frontend shows approval card with:
    - What the agent wants to do
    - Why (reasoning from structured output)
    - Risk assessment
    - Planned actions
  → User clicks Approve / Modify / Abort
  → Response flows back through WebSocket → Redis → Agent
  → Agent proceeds or adjusts based on response
```

#### 4.3 Autonomous Mode (Current Behavior)
When `approval_gates` are all `false` (or `exploit_mode: "autonomous"`), the agent runs without waiting — current TazoSploit behavior preserved.

#### 4.4 Files to Modify
- `dynamic_agent.py` — add approval check before phase transitions
- `control-plane/api/` — approval endpoints
- `frontend/` — approval card UI components
- API schema: add `approval_gates` to `JobCreate`

#### 4.5 Estimated Effort: 1-2 days

---

## Implementation Order

| Phase | Feature | Effort | Dependencies |
|-------|---------|--------|--------------|
| **Phase 1** | Structured ReAct Output | 1-2 days | None |
| **Phase 2** | Neo4j Knowledge Graph | 2-3 days | Phase 1 (structured data feeds graph) |
| **Phase 3** | Real-Time Chat + Guidance | 3-4 days | Phase 1 (structured output enables streaming) |
| **Phase 4** | Approval Gates | 1-2 days | Phase 3 (needs WebSocket infra) |

**Total estimated effort: 7-11 days**

### Why This Order?
1. **Structured output first** — everything else builds on having structured agent steps
2. **Neo4j second** — structured data populates the graph cleanly
3. **Chat third** — structured output + graph enable rich streaming to the chat
4. **Approval gates last** — simple addition once WebSocket infra exists from chat feature

---

## What We Keep (TazoSploit Advantages)

These existing features are BETTER than RedAmon — don't replace them:

- ✅ Vulnerability tracker with attempt counts and proof status
- ✅ Evidence detection (12+ regex patterns)
- ✅ Supervisor with escalation ladder
- ✅ Context summarization and digest system
- ✅ Artifact extraction (credentials, tokens, keys)
- ✅ Command policy enforcement (10+ pre-execution checks)
- ✅ 125 skills with MITRE mapping
- ✅ Direct Kali CLI execution (better than MCP wrappers)
- ✅ Multi-container parallel execution
- ✅ Session handoff between containers

---

## UI Overhaul (Separate Track)

Not in this plan but noted for future:
- Model selector dropdown (all providers + models)
- Project-based navigation
- Neo4j graph visualization (interactive attack surface map)
- Professional design refresh
- Settings exposed in UI (not just .env/JSON)
- Real-time agent dashboard with metrics
