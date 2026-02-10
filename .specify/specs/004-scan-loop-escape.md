# Spec 004: Agent Scan Loop Detection & Escape

## Problem Statement

The Dynamic Agent frequently gets stuck in enumeration loops: running nmap, gobuster, nikto, whatweb, and curl in cycles without ever attempting exploitation. The supervisor detects this via `scan_loop` alerts, but:

1. The agent-side detection is only in the supervisor (external), not in the agent itself
2. The supervisor's hint arrives asynchronously and may be too late
3. The agent's system prompt says "exploitation bias" but the LLM often ignores it
4. There's no hard gate forcing the agent to attempt exploitation after N enum iterations

### Observed Pattern
```
Iteration 1-5: nmap, whatweb, gobuster (good — baseline recon)
Iteration 6-10: nikto, nuclei, more gobuster with different wordlists (diminishing returns)
Iteration 11-20: re-running nmap with different flags, curl-ing endpoints already found (waste)
Iteration 21+: still scanning, zero exploit attempts
```

## Proposed Solution

### 1. Agent-Internal Phase Escalation Gate

Add a hard gate in the Dynamic Agent that forces exploitation after N enumeration-only iterations:

```python
class DynamicAgent:
    def __init__(self, ...):
        self.enum_only_streak = 0
        self.max_enum_streak = int(os.getenv("MAX_ENUM_STREAK_BEFORE_EXPLOIT", "8"))
        self.exploit_attempted = False
    
    def _check_enum_streak(self, cmd: str) -> Optional[str]:
        """Track enum-only streaks and force exploitation."""
        intent = _classify_cmd_intent(cmd)
        if intent == "exploit":
            self.enum_only_streak = 0
            self.exploit_attempted = True
            return None
        elif intent == "enum":
            self.enum_only_streak += 1
        
        if self.enum_only_streak >= self.max_enum_streak and not self.exploit_attempted:
            self.enum_only_streak = 0  # Reset to avoid spam
            return (
                "⚠️ EXPLOITATION REQUIRED: You have run {count} enumeration commands "
                "without any exploitation attempt. You MUST now attempt exploitation. "
                "Review discovered services/vulns and run sqlmap, commix, hydra, or manual exploit."
            ).format(count=self.max_enum_streak)
        return None
```

### 2. Exploit Readiness Scoring

Track what the agent has discovered and compute an "exploit readiness" score:

```python
def _exploit_readiness_score(self) -> dict:
    """Score how ready we are to exploit based on gathered intelligence."""
    score = 0
    reasons = []
    
    evidence = self._load_evidence_context()
    
    if evidence.get("vulns"):
        score += 40
        reasons.append("Vulnerabilities identified")
    if evidence.get("creds"):
        score += 30
        reasons.append("Credentials found")
    if self.recon_baseline_complete:
        score += 20
        reasons.append("Baseline recon complete")
    if len(self.covered_targets) > 0:
        score += 10
        reasons.append(f"{len(self.covered_targets)} targets covered")
    
    return {"score": score, "reasons": reasons, "ready": score >= 40}
```

### 3. Dynamic System Prompt Injection

When the readiness score exceeds threshold, inject an urgent exploitation directive into the conversation:

```python
if readiness["ready"] and not self.exploit_attempted:
    exploit_push = (
        f"\n\n**URGENT: EXPLOIT NOW**\n"
        f"Readiness: {readiness['score']}/100 ({', '.join(readiness['reasons'])})\n"
        f"Stop scanning. Pick the highest-severity finding and exploit it.\n"
        f"If SQLi found: `sqlmap --dump`. If creds found: use them. If upload found: test RCE."
    )
    self.conversation.append({"role": "user", "content": exploit_push})
```

### 4. Enum Budget Per Target

Limit enumeration commands per target:
```python
MAX_ENUM_PER_TARGET = int(os.getenv("MAX_ENUM_PER_TARGET", "15"))

def _enum_budget_exceeded(self, target: str) -> bool:
    enum_count = sum(1 for cmd in self.recent_commands 
                     if target in cmd and _classify_cmd_intent(cmd) == "enum")
    return enum_count >= MAX_ENUM_PER_TARGET
```

## Acceptance Criteria
- [ ] Agent attempts exploitation within 10 iterations (configurable) of first vulnerability discovery
- [ ] After MAX_ENUM_STREAK iterations of pure scanning, the next command MUST be exploit-oriented
- [ ] Exploit readiness score is logged and visible in job stats
- [ ] Per-target enum budget prevents excessive scanning of a single target
- [ ] Supervisor scan_loop alerts decrease by >50% with this fix

## Files to Modify
- `kali-executor/open-interpreter/dynamic_agent.py` — Add enum streak tracking, readiness scoring, budget enforcement
- `execution-plane/supervisor/main.py` — Adjust scan_loop thresholds (may be less aggressive with agent-side fix)

## Risk Assessment
- **Medium**: Hard gates may block legitimate deep enumeration (mitigate with configurable thresholds)
- **Low**: Readiness scoring is purely advisory when below threshold
