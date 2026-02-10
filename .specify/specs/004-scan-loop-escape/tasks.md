# Tasks: 004 Scan Loop Detection & Escape

**Input**: spec.md + plan.md
**Target File**: `kali-executor/open-interpreter/dynamic_agent.py`

## Phase 1: Enum Streak Counter (MVP)

- [ ] T001 Add state variables to `__init__` (near line ~380):
  - `self.enum_only_streak = 0`
  - `self.max_enum_streak = int(os.getenv("MAX_ENUM_STREAK_BEFORE_EXPLOIT", "8"))`
  - `self.total_exploit_attempts = 0`

- [ ] T002 Add `_check_enum_streak(self, cmd: str) -> Optional[str]` method:
  - Classify command intent using existing `_classify_command_intent(cmd)`
  - If `exploit` intent: reset `enum_only_streak` to 0, increment `total_exploit_attempts`, return None
  - If `enum` intent: increment `enum_only_streak`
  - If streak ≥ `max_enum_streak` AND `self.vulns_found` has entries:
    - Reset streak counter
    - Pick top unproven vuln from tracker
    - Return urgent directive: "⚠️ EXPLOITATION REQUIRED: {streak} enum commands without exploit. Focus on {vuln_type} at {target}."
    - Include 2 concrete command templates from `_get_exploit_templates_for_vuln()` (from Spec 006)
  - Otherwise return None

- [ ] T003 Integrate `_check_enum_streak()` into main loop:
  - After command extraction, before execution (near line ~2875)
  - Call `_check_enum_streak(cmd)` for each extracted command
  - If returns a message, append to conversation as user message
  - Set `self.force_exploit_next = True` to engage existing exploit-only gate

- [ ] T004 Test: Run job against Juice Shop, verify enum streak triggers after 8 consecutive enum commands

**Checkpoint**: Agent gets pushed to exploit after sustained scanning streaks

## Phase 2: Exploit Readiness Scoring

- [ ] T005 Add `_exploit_readiness_score(self) -> dict` method:
  - Score vulns_found has entries → +40
  - Score evidence/credentials.json exists and non-empty → +30
  - Score `self.recon_phase_complete` or `self.recon_baseline_complete` → +20
  - Score `len(self.covered_targets) > 0` → +10
  - Return `{"score": int, "reasons": list[str], "ready": score >= 40}`

- [ ] T006 Add `_build_readiness_exploit_push(self, readiness: dict) -> str` method:
  - Build message: "**EXPLOIT NOW** — Readiness: {score}/100"
  - List reasons (what triggered readiness)
  - Pick highest-priority unproven vuln
  - Include 2-3 specific command templates for that vuln
  - Include "DO NOT run more nmap/gobuster/nikto"

- [ ] T007 Integrate readiness push into main loop (near line ~2770, before exploit gate):
  - Compute readiness score
  - If `readiness["ready"]` AND `self.total_exploit_attempts == 0` AND `self.iteration >= 10`:
    - Inject push message
    - Set a flag `self._readiness_push_fired = True` to prevent repeat
  - Log readiness score every 10 iterations for debugging

- [ ] T008 Test: Verify readiness score logs appear, push fires once when vulns are found

**Checkpoint**: Agent gets a one-time strong push to start exploiting when ready

## Phase 3: Per-Target Enum Budget

- [ ] T009 Add `self.target_enum_counts: Dict[str, int] = {}` to `__init__`
- [ ] T010 Add `self.max_enum_per_target = int(os.getenv("MAX_ENUM_PER_TARGET", "15"))` to `__init__`

- [ ] T011 Add `_enum_budget_exceeded(self, target: str) -> bool` method:
  - Look up `self.target_enum_counts.get(target, 0)`
  - Return True if count ≥ `max_enum_per_target`

- [ ] T012 Track enum commands per target:
  - In `_save_execution()` or post-execution path, after classifying intent
  - If intent is `enum`, extract target from command and increment `target_enum_counts[target]`
  - Use `_extract_target_from_command()` (new helper) to parse target from nmap/gobuster/curl commands

- [ ] T013 Integrate budget check into command execution path:
  - Before executing enum command, check `_enum_budget_exceeded(target)`
  - If exceeded (1x budget): inject warning "⚠️ ENUM BUDGET: Switch to exploitation for {target}"
  - If exceeded (2x budget, ≥30): hard-block the command and reprompt for exploit

- [ ] T014 Test: Verify enum budget warnings appear after 15 enum commands for same target

**Checkpoint**: Per-target scanning is bounded

## Phase 4: Polish & Integration

- [ ] T015 Verify all three mechanisms (streak, readiness, budget) work together without conflicts
- [ ] T016 Verify coexistence with existing `_scan_loop_detected()` — no duplicate pushes within same iteration
- [ ] T017 Run full Juice Shop job end-to-end, verify agent exploits earlier than baseline
- [ ] T018 Document changes in commit message referencing spec 004

## Dependencies

- T001 → T002 → T003 → T004 (sequential streak pipeline)
- T005 → T006 → T007 → T008 (sequential readiness pipeline)
- T009, T010 → T011 → T012 → T013 → T014 (sequential budget pipeline)
- T015-T018 depend on all above
- Spec 006 (`_get_exploit_templates_for_vuln()`) is a soft dependency — if not yet implemented, T002 falls back to generic exploit suggestions
