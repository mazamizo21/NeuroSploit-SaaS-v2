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
Add a hard gate in the Dynamic Agent that forces exploitation after N enumeration-only iterations. Track `enum_only_streak` counter, reset on any exploit-intent command. When streak exceeds `MAX_ENUM_STREAK_BEFORE_EXPLOIT` (default 8), inject an urgent exploit directive.

### 2. Exploit Readiness Scoring
Track what the agent has discovered and compute an "exploit readiness" score based on: vulns identified (40pts), creds found (30pts), baseline recon complete (20pts), targets covered (10pts). When score ≥ 40 and no exploits attempted, push exploitation.

### 3. Dynamic System Prompt Injection
When the readiness score exceeds threshold, inject an urgent exploitation directive into the conversation with specific guidance based on what's been discovered.

### 4. Enum Budget Per Target
Limit enumeration commands per target via `MAX_ENUM_PER_TARGET` (default 15). Once exceeded, block further enum commands and force exploitation focus.

## Acceptance Criteria
- [ ] Agent attempts exploitation within 10 iterations (configurable) of first vulnerability discovery
- [ ] After MAX_ENUM_STREAK iterations of pure scanning, the next command MUST be exploit-oriented
- [ ] Exploit readiness score is logged and visible in job stats
- [ ] Per-target enum budget prevents excessive scanning of a single target
- [ ] Supervisor scan_loop alerts decrease by >50% with this fix

## Constraints
- ALL changes in `kali-executor/open-interpreter/dynamic_agent.py` only
- Must work with weak LLMs (GLM 4.7) — hard gates, not soft suggestions
- Must not break existing exploit gate logic (complement it)
- Configurable via environment variables with sensible defaults
- Backward compatible with existing vuln_tracker schema

## Files to Modify
- `kali-executor/open-interpreter/dynamic_agent.py` — Add enum streak tracking, readiness scoring, budget enforcement

## Risk Assessment
- **Medium**: Hard gates may block legitimate deep enumeration (mitigate with configurable thresholds)
- **Low**: Readiness scoring is purely advisory when below threshold
