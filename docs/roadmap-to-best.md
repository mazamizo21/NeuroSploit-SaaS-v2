# TazoSploit — Roadmap to Best-in-Class

## The Core Problem (honest diagnosis)

TazoSploit has the **best arsenal** of any AI pentest tool — 125 skills, 265 MITRE IDs, full Kali CLI access. But the LLM agent ignores 95% of it and loops on nmap/curl.

The problem isn't tools. It's **architecture**. The agent has freedom but no structure. RedAmon has structure but no freedom. The best tool has **both**.

---

## Priority 1: Fix the Exploitation Gap (CRITICAL — do this first)

### 1A. Tool Usage Tracker + Comfort Zone Breaker

**Problem:** Agent uses 8 tools out of 125+. Gravitates to nmap/curl/masscan.

**Solution:** Track tool usage per-job in Redis. After thresholds, force diversity.

```python
# In dynamic_agent.py — after command extraction, before execution
class ToolUsageTracker:
    def __init__(self, job_id, redis_client):
        self.key = f"job:{job_id}:tool_usage"
    
    def record(self, tool_name):
        self.redis.hincrby(self.key, tool_name, 1)
    
    def get_usage(self):
        return self.redis.hgetall(self.key)
    
    def should_force_diversity(self, iteration):
        usage = self.get_usage()
        unique_tools = len(usage)
        # After 20 iterations with <4 unique tools → inject diversity prompt
        if iteration > 20 and unique_tools < 4:
            return True
        # Any single tool used >8 times → hard suggest alternatives
        for tool, count in usage.items():
            if int(count) > 8:
                return True
        return False
    
    def get_unused_relevant_tools(self, phase, findings):
        """Return tools the agent SHOULD be using but isn't"""
        # Maps findings → recommended tools
        tool_map = {
            "smb_open": ["crackmapexec", "smbclient", "enum4linux", "impacket"],
            "http_open": ["sqlmap", "nikto", "gobuster", "ffuf", "nuclei"],
            "rdp_open": ["hydra", "crowbar", "xfreerdp"],
            "ssh_open": ["hydra", "ssh-audit"],
            "mssql_open": ["crackmapexec", "sqsh", "impacket-mssqlclient"],
            "winrm_open": ["evil-winrm", "crackmapexec"],
            "cve_found": ["metasploit", "searchsploit"],
            "creds_found": ["crackmapexec", "evil-winrm", "impacket-psexec"],
        }
        # ... compare against actual usage, return unused
```

**Inject prompt when triggered:**
```
⚠️ TOOL DIVERSITY ALERT: You've used {used_tools} for {N} iterations.
Based on your findings ({findings}), you should be using: {unused_tools}
Your NEXT command MUST use one of: {specific_suggestions}
Do NOT run another {overused_tool} command.
```

### 1B. Phase State Machine (not just a label)

**Problem:** "FULL" phase = agent decides when to move from scanning to exploiting. It never decides.

**Solution:** Hard phase transitions enforced by the system, not the agent.

```
RECON (max 15 iterations)
  → System auto-transitions when: ports found OR 15 iters reached
  
ENUMERATE (max 20 iterations)  
  → System auto-transitions when: services fingerprinted OR 20 iters reached
  
EXPLOIT (min 30 iterations, no max)
  → Agent CANNOT run scan commands in this phase
  → Only exploitation tools allowed: sqlmap, hydra, metasploit, crackmapexec, etc.
  → Custom python/bash scripts allowed IF they contain exploitation logic
  
POST-EXPLOIT (triggered by: shell gained OR creds found)
  → Privesc, lateral movement, data exfiltration
  → Auto-inject post-exploit checklist
```

**Key change:** The phase isn't a suggestion. It's a hard gate. In EXPLOIT phase, nmap/masscan are BLOCKED (not just warned — blocked). The agent has to use exploitation tools.

### 1C. Proactive Command Injection (the biggest missing piece)

**Problem:** Supervisor can inject commands, but it's reactive. Agent has to fail first.

**Solution:** After ENUMERATE phase, system analyzes findings and INJECTS specific exploitation commands.

```python
class ExploitationInjector:
    """Analyzes scan results and generates specific exploit commands"""
    
    def generate_exploitation_plan(self, findings):
        plan = []
        
        for finding in findings:
            if finding.port == 445 and finding.service == "smb":
                plan.append({
                    "tool": "crackmapexec",
                    "command": f"crackmapexec smb {finding.host} -u users.txt -p passwords.txt",
                    "rationale": "SMB open — try credential brute force",
                    "fallback": f"nmap --script smb-vuln-* -p445 {finding.host}"
                })
                if finding.smb_signing_disabled:
                    plan.append({
                        "tool": "responder",
                        "command": f"responder -I eth0 -dwP",
                        "rationale": "SMB signing disabled — relay attack possible"
                    })
            
            if finding.port in [80, 443, 8080] and finding.has_web_app:
                plan.append({
                    "tool": "sqlmap",
                    "command": f"sqlmap -u '{finding.url}' --batch --forms --crawl=2",
                    "rationale": "Web app found — test for SQL injection",
                    "fallback": f"nuclei -u {finding.url} -severity critical,high"
                })
            
            if finding.cve:
                plan.append({
                    "tool": "metasploit",
                    "command": f"msfconsole -q -x 'search {finding.cve}; exit'",
                    "rationale": f"CVE found — check Metasploit for exploit module"
                })
        
        return plan
```

Inject as system message:
```
🎯 EXPLOITATION PLAN (based on your reconnaissance):

1. SMB on port 445 → Run: crackmapexec smb TARGET -u Administrator -p passwords.txt
2. HTTP on port 8080 → Run: sqlmap -u 'http://TARGET:8080/' --batch --forms
3. CVE-2021-34527 found → Run: msfconsole -q -x 'search CVE-2021-34527'

Execute these IN ORDER. Do not scan again. EXPLOIT.
```

---

## Priority 2: Knowledge Graph (HIGH — biggest architectural upgrade)

### 2A. Neo4j Integration (steal from RedAmon, do it better)

**Why:** The agent forgets what it's tried. Repeats scans. Loses track of credentials across services. Neo4j solves all of this.

**Schema:**
```cypher
// Nodes
(:Host {ip, hostname, os, status})
(:Service {port, protocol, name, version, banner})
(:Vulnerability {cve, title, severity, verified})
(:Credential {username, password, hash, source})
(:ExploitAttempt {tool, command, result, timestamp})
(:Finding {title, evidence, severity, mitre_technique})

// Relationships
(host)-[:RUNS]->(service)
(service)-[:HAS_VULN]->(vuln)
(vuln)-[:EXPLOITED_BY]->(attempt)
(attempt)-[:YIELDED]->(finding)
(attempt)-[:USED_CRED]->(cred)
(cred)-[:WORKS_ON]->(service)
(host)-[:LATERAL_TO]->(host)
```

**Agent can query:**
- "What services haven't been attacked yet?" → forces new exploitation targets
- "What credentials have I found?" → enables credential reuse across services
- "What tools have I NOT tried on port 445?" → breaks comfort zone
- "Show me the full attack path from initial access to current position" → reasoning

**Implementation:**
- Neo4j container added to docker-compose
- `knowledge_graph.py` module wraps Cypher queries
- After every command execution, results are parsed and stored in graph
- Before every agent turn, inject graph summary into context
- Agent can explicitly query graph via special commands

### 2B. Attack Surface Reasoning (the killer feature)

RedAmon queries Neo4j but only for basic retrieval. TazoSploit should use it for **reasoning**:

```python
def get_exploitation_suggestions(self):
    """Query graph for unexploited attack surface"""
    query = """
    MATCH (h:Host)-[:RUNS]->(s:Service)
    WHERE NOT EXISTS {
        MATCH (s)<-[:TARGETED]-(a:ExploitAttempt)
        WHERE a.result = 'success'
    }
    WITH s, h, 
         CASE WHEN EXISTS((s)-[:HAS_VULN]->()) THEN 10 ELSE 1 END AS priority
    RETURN h.ip, s.port, s.name, s.version, 
           collect([(s)-[:HAS_VULN]->(v) | v.cve]) as vulns
    ORDER BY priority DESC
    LIMIT 5
    """
    return self.graph.run(query)
```

This gives the agent a **ranked list of unexploited services** every iteration. No more "what should I do next?" — the graph TELLS it.

---

## Priority 3: Structured Output (MEDIUM)

### 3A. ReAct Loop with JSON Schema

**Problem:** Agent outputs free-form text. Sometimes it reasons, sometimes it doesn't. No consistent structure.

**Solution:** Require structured JSON for each turn:

```json
{
  "thought": "Port 445 is open with SMB signing disabled. I should try relay attacks.",
  "phase": "EXPLOIT",
  "target": "192.168.4.125:445",
  "tool": "responder",
  "command": "responder -I eth0 -dwP",
  "expected_outcome": "Capture NetNTLM hashes from SMB relay",
  "fallback_if_fails": "crackmapexec smb 192.168.4.125 -u admin -p passwords.txt",
  "mitre_technique": "T1557.001"
}
```

**Benefits:**
- Tool usage tracking becomes trivial (parse `tool` field)
- Phase enforcement is explicit (`phase` field)
- Fallback chains are pre-planned, not improvised
- MITRE mapping is built-in
- Easy to store in Neo4j

### 3B. Multi-Step Planning

Before each exploitation attempt, require a plan:

```json
{
  "plan": [
    {"step": 1, "tool": "crackmapexec", "action": "Brute force SMB with common passwords"},
    {"step": 2, "tool": "evil-winrm", "action": "If creds found, get shell via WinRM"},
    {"step": 3, "tool": "mimikatz", "action": "Dump credentials from memory"},
    {"step": 4, "tool": "crackmapexec", "action": "Use dumped creds for lateral movement"}
  ]
}
```

Agent commits to a plan. System tracks progress through it. If agent tries to deviate back to nmap, system says "You're on step 2 of your plan. Execute it."

---

## Priority 4: Smart Model Routing (MEDIUM)

### 4A. Task-Specific Model Selection

Not every iteration needs Opus. Use the right model for the right task:

| Task | Model | Why |
|------|-------|-----|
| Port scan analysis | Flash/Haiku | Simple parsing, cheap |
| Exploitation planning | Opus | Complex reasoning needed |
| Command generation | Sonnet | Good enough, 5x cheaper |
| Evidence verification | Opus | Critical accuracy |
| Report generation | Sonnet | Template-based |

**Savings estimate:** 60-70% cost reduction per job. A $13 job becomes $4-5.

### 4B. Specialist Sub-Agents

Instead of one monolithic agent, use specialist sub-agents:

- **Recon Agent** (cheap model) — handles scanning, port discovery, fingerprinting
- **Exploit Agent** (expensive model) — handles exploitation planning and execution
- **Post-Exploit Agent** (expensive model) — handles privesc, lateral movement
- **Report Agent** (cheap model) — compiles findings into report

Each agent has a focused system prompt and restricted tool access. The Recon Agent literally CAN'T run nmap after phase transition — it's not in its toolset.

---

## Priority 5: UI Overhaul (LOWER — but important for product)

### 5A. Steal from RedAmon's UI

Their Next.js frontend is genuinely better:
- Model selector dropdown (pick model per-job)
- Real-time attack graph visualization (Neo4j → D3.js)
- Human-in-the-loop approval gates for dangerous commands
- Structured phase indicators (not just iteration count)

### 5B. Attack Graph Visualization

With Neo4j, visualize:
- Network topology (hosts → services → vulns)
- Attack path (initial access → current position)
- Tool usage heatmap (which tools used, which neglected)
- Phase progress (recon ████░░░░ exploit)

---

## Implementation Order

### Sprint 1 (Week 1-2): Fix the Core Loop
1. Tool Usage Tracker + Comfort Zone Breaker → `dynamic_agent.py`
2. Phase State Machine (hard transitions) → `dynamic_agent.py`
3. Proactive Command Injection → `exploitation_injector.py` (new)

### Sprint 2 (Week 3-4): Knowledge Graph
4. Neo4j container + docker-compose
5. `knowledge_graph.py` module
6. Command result → graph parser
7. Graph context injection into agent turns

### Sprint 3 (Week 5-6): Structured Output
8. JSON schema for agent output
9. ReAct loop enforcement
10. Multi-step planning system

### Sprint 4 (Week 7-8): Model Routing + Polish
11. Task-specific model routing
12. Sub-agent architecture
13. UI improvements (model dropdown, attack graph viz)

---

## What Makes This "The Best"

| Feature | TazoSploit (current) | RedAmon | TazoSploit (roadmap) |
|---------|---------------------|---------|---------------------|
| Tool arsenal | 125+ skills | 2 attack paths (Metasploit only) | 125+ skills, ENFORCED usage |
| Exploitation | Agent ignores tools | Metasploit-only via MCP | Phase-gated + command injection |
| Knowledge | No memory between iterations | Neo4j graph | Neo4j + attack surface reasoning |
| Architecture | Monolithic 9500-line agent | LangGraph + StateGraph | Phase state machine + sub-agents |
| Output | Free-form text | Structured JSON | ReAct JSON + multi-step plans |
| Cost | $13/job (Opus everywhere) | Unknown | $4-5/job (smart routing) |
| Evidence | 12+ regex patterns | None (LLM decides) | Regex + graph-validated + LLM |
| Supervisor | Reactive (waits for failure) | None | Proactive (injects exploitation) |
| UI | Basic | Production-grade | Attack graph + model selector |

**The winning formula:** TazoSploit's arsenal + RedAmon's structure + knowledge graph + proactive exploitation = best AI pentest tool.

The agent doesn't need more tools. It needs to be FORCED to use the tools it already has, guided by a knowledge graph that tells it what's been tried and what hasn't, with hard phase gates that prevent scanning loops.

---

## Future Enhancement: Dynamic Recon Budget by Target Type

**Observed:** Phase machine RECON budget is hardcoded at 5 steps (`PHASE_RECON_MAX_STEPS=5`).
This works great for single-service web apps (Juice Shop) — agent finds SQLi by iter 6 and
moves straight to exploitation. But for multi-service targets (Windows VulnLab, enterprise
networks), 5 recon steps isn't enough to discover all attack surfaces via nmap.

**Problem:** Agent skips nmap entirely because the phase gate pushes it to EXPLOITATION before
a full port scan completes. `nmap` is only allowed in `["RECON", "VULN_DISCOVERY"]` phases
per the tool_phase_map — once in EXPLOITATION, it's blocked.

**Proposed fix:** Dynamic recon budget based on target type / scope:

```python
# In dynamic_agent.py or project_settings.py
RECON_BUDGETS = {
    "web_app": 5,       # Single web target — fast recon, go exploit
    "network": 20,      # Multi-port/multi-host — needs full nmap
    "enterprise": 40,   # Full enterprise scope — thorough recon required
}

# Auto-detect from scope:
# - Single hostname + port 80/443/3000/8080 → web_app
# - IP range / CIDR → network
# - Multiple targets in scope → enterprise
```

**Implementation options:**
1. Add `target_type` hint to scope config (already have `lab`/`external`)
2. Auto-classify from target format (hostname vs IP range vs CIDR)
3. Let the phase machine adapt: if nmap finds >3 open ports, extend recon budget dynamically
4. Make it a job-level setting: `recon_budget_override` in JobCreate API

**Priority:** Medium — current budget works for web app CTFs, needs fix before network pentests.
**Added:** 2026-02-16 after observing Juice Shop job f177a265 skip nmap entirely.
