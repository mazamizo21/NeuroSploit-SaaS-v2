# Spec 002: Supervisor LLM Fallback Improvement

## Problem Statement

When the supervisor's LLM calls fail (429 rate limit, 5xx errors, timeouts), it falls back to stub decisions that are simple, static heuristics. These stub decisions are acceptable for basic cases but miss nuanced situations like:

- Scan loops where the agent needs specific exploit guidance (not just "stop scanning")
- Stalls caused by tool installation failures (where retrying the same approach won't help)
- Multi-target scenarios where the agent should pivot to a different target

### Current Stub Behavior
```python
def _stub_audit(self, alert_type, data, context):
    # Returns static hint based on alert_type only
    # Ignores: recent commands, iteration count, findings, target coverage
```

The stub doesn't use any of the rich context available in `data` and `context` parameters.

## Proposed Solution

### 1. Context-Aware Stub Decisions

Replace the static stub with a rule-based decision tree that uses context:

```python
def _smart_stub_audit(self, alert_type, data, context):
    recent_cmds = context.get("recent_commands", [])
    iteration = context.get("current_iteration", 0)
    max_iter = context.get("max_iterations", 100)
    stats = context.get("live_stats", {})
    findings = int(stats.get("total_findings", 0))
    
    # If we're past 70% of iterations with no findings, escalate
    if max_iter and iteration / max_iter > 0.7 and findings == 0:
        return {
            "action": "reset",
            "severity": "high",
            "hint": "70%+ iterations consumed with zero findings. Full strategy reset needed.",
            "next_strategy": "Start fresh: quick nmap, pick top 3 services, try one exploit each."
        }
    
    # Scan loop with specific tool guidance
    if alert_type == "scan_loop":
        enum_cmds = [c for c in recent_cmds if _classify_cmd_intent(c) == "enum"]
        if any("nmap" in c for c in enum_cmds):
            return {
                "action": "hint",
                "severity": "medium",
                "hint": "Stop nmap scanning. You have enough port data.",
                "next_strategy": "Run sqlmap against discovered web forms or hydra against found login pages."
            }
    
    # Repeated command with specific escape
    if alert_type == "repeated_command":
        repeated_cmd = data.get("command", "")
        return {
            "action": "hint",
            "severity": "medium",
            "hint": f"Stop running '{repeated_cmd[:60]}'. This has failed multiple times.",
            "next_strategy": "Try a completely different tool or attack vector."
        }
```

### 2. Escalation Tiers Without LLM

Add a tiered escalation system that works without LLM:
- **Tier 1 (first alert)**: Gentle hint with specific tool suggestion
- **Tier 2 (second alert, same type)**: Stronger directive with explicit next command
- **Tier 3 (third alert)**: Conversation reset with fresh strategy
- **Tier 4 (fourth alert)**: Job cancellation if no progress

Track tier per job per alert type:
```python
@dataclass
class JobState:
    alert_escalation: Dict[str, int] = field(default_factory=dict)  # {alert_type: tier}
```

### 3. LLM Recovery with Backoff

Instead of permanently falling back to stub after one failure, implement exponential backoff with periodic LLM retry:

```python
class Supervisor:
    def __init__(self):
        self._llm_backoff = 0  # seconds until next LLM attempt
        self._llm_last_fail = 0
    
    async def _audit_decision(self, ...):
        now = time.time()
        if self._llm_backoff and now - self._llm_last_fail < self._llm_backoff:
            # Still in backoff, use smart stub
            return self._smart_stub_audit(...)
        
        try:
            decision = await self._call_llm(...)
            self._llm_backoff = 0  # Reset on success
            return decision
        except Exception as e:
            self._llm_last_fail = now
            self._llm_backoff = min(self._llm_backoff * 2 or 30, 300)  # 30s → 60s → 120s → 300s max
            return self._smart_stub_audit(...)
```

## Acceptance Criteria
- [ ] Stub decisions use context (recent commands, iteration progress, findings count)
- [ ] Escalation tiers progress from hint → reset → cancel
- [ ] LLM calls recover after backoff period expires
- [ ] Stub quality measured: >50% of stub hints result in agent behavior change within 3 iterations

## Files to Modify
- `execution-plane/supervisor/main.py` — Replace `_stub_audit`, add escalation tiers, add backoff

## Risk Assessment
- **Low**: Smart stubs are still deterministic and safe
- **Medium**: Escalation to `reset` can lose context — mitigate by preserving evidence summary
