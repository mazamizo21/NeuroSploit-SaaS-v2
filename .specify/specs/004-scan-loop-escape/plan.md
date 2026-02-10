# Plan: 004 Scan Loop Detection & Escape

**Branch**: `004-scan-loop-escape` | **Date**: 2026-02-08 | **Spec**: spec.md

## Summary

Add agent-internal scan loop detection and escape mechanisms to complement the external supervisor. Four changes: (1) enum streak counter with hard gate, (2) exploit readiness scoring, (3) dynamic exploitation directives, (4) per-target enum budgets.

## Technical Context

**Language/Version**: Python 3.11+
**Primary File**: `kali-executor/open-interpreter/dynamic_agent.py` (~4673 lines)
**Testing**: Manual E2E via Docker Compose against Juice Shop lab
**Constraints**: Changes must coexist with existing `_scan_loop_detected()` (line ~3545) and exploit gate logic (lines 2770-2800, 2875-2960)

## Constitution Check

- ✅ Evidence-First Exploitation — reinforces exploitation, does not weaken proof gate
- ✅ No Hardcoded Exploits — readiness scoring is heuristic, not hardcoded paths
- ✅ Separation of Concerns — changes limited to Kali Plane (Dynamic Agent)
- ✅ Supervisor Independence — complements, does not replace supervisor scan_loop detection

## Changes Required

All changes in `kali-executor/open-interpreter/dynamic_agent.py`:

### 1. Enum Streak Counter & Hard Gate

**Location**: `__init__` (line ~345) + new method + main loop integration

Add state variables:
```python
# In __init__
self.enum_only_streak = 0
self.max_enum_streak = int(os.getenv("MAX_ENUM_STREAK_BEFORE_EXPLOIT", "8"))
self.total_exploit_attempts = 0
```

New method `_check_enum_streak(self, cmd: str) -> Optional[str]`:
- Uses existing `_classify_command_intent()` to determine if command is enum/exploit
- Increments `enum_only_streak` on enum, resets on exploit
- When streak ≥ threshold AND vulns exist in tracker, returns a hard exploit directive
- Directive includes top unproven vuln from tracker + specific commands to try

**Integration point**: In main loop, after command extraction, before execution (near line ~2875 where exploit-only hard gate runs). Check streak BEFORE allowing the command through.

### 2. Exploit Readiness Scoring

**Location**: New method `_exploit_readiness_score(self) -> dict`

Scoring algorithm:
- `vulns_found` has entries → +40 points
- Credentials found (check evidence/credentials.json or vuln evidence) → +30 points
- `recon_baseline_complete` or `recon_phase_complete` is True → +20 points
- `covered_targets` has entries → +10 points
- Returns `{"score": int, "reasons": list, "ready": bool}` where ready = score ≥ 40

**No external dependencies** — reads only from existing agent state.

### 3. Readiness-Triggered Exploitation Push

**Location**: Main loop, after context pack but before LLM call (near line ~2770)

Logic:
```python
readiness = self._exploit_readiness_score()
if readiness["ready"] and self.total_exploit_attempts == 0 and self.iteration >= 10:
    # Inject exploitation push with readiness context
    push_msg = self._build_readiness_exploit_push(readiness)
    self.conversation.append({"role": "user", "content": push_msg})
```

Only triggers ONCE (when first ready and no exploits attempted yet). After that, the existing exploit gate handles ongoing exploitation pressure.

### 4. Per-Target Enum Budget

**Location**: New method + integration in command execution path

New method `_enum_budget_exceeded(self, target: str) -> bool`:
- Counts enum-classified commands targeting this specific target from `self.executions`
- Compares against `MAX_ENUM_PER_TARGET` (env var, default 15)
- Returns True when exceeded

Integration: When budget exceeded and command intent is enum, inject warning message and allow but tag:
```python
"⚠️ ENUM BUDGET: {count}/{max} enum commands used for {target}. Switch to exploitation."
```
After 2x budget (30 commands), hard-block further enum and force exploit mode for that target.

### 5. Interaction with Existing Code

**`_scan_loop_detected()` (line ~3545)**: Existing method checks window of 25 recent commands for 70% enum ratio. The new enum streak counter is complementary — it catches sustained streaks even when the window ratio isn't triggered (e.g., if the agent alternates 1 exploit attempt per 8 enum commands).

**Exploit gate (lines 2770-2800)**: The readiness push fires BEFORE the exploit gate cooldown logic, so it can trigger even when the cooldown timer hasn't expired. However, it only fires once (first time ready), so it doesn't conflict with the periodic gate.

**Exploit-only hard gate (lines 2875-2960)**: The enum streak hard gate runs at a different checkpoint — it evaluates BEFORE command execution, while the exploit-only gate evaluates AFTER the LLM response. They're complementary: streak gate prevents accumulation, exploit-only gate enforces the forced state.

## Method Signatures

```python
def _check_enum_streak(self, cmd: str) -> Optional[str]:
    """Check if enum streak exceeds threshold. Returns exploit push message or None."""

def _exploit_readiness_score(self) -> dict:
    """Compute exploit readiness score. Returns {score, reasons, ready}."""

def _build_readiness_exploit_push(self, readiness: dict) -> str:
    """Build readiness-based exploit push message with vuln context."""

def _enum_budget_exceeded(self, target: str) -> bool:
    """Check if enum command budget for a target is exceeded."""
```

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Hard gate blocks legitimate deep enum | Configurable threshold (env var), only triggers after vulns found |
| Readiness scoring false positives | Score requires ≥40 (vulns must exist), fires only once |
| Enum budget too restrictive | Default 15 is generous; hard block at 2x (30) |
| Conflicts with existing exploit gate | Different trigger conditions, complementary not overlapping |
