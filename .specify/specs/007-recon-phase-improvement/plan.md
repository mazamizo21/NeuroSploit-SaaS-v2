# Plan: 007 Recon Phase Improvement

## Implementation Strategy

All changes in `kali-executor/open-interpreter/dynamic_agent.py` (4533 lines). Surgical edits only — no full rewrites.

## Change Areas

### 1. Scope-Validated Finding Submission (US-1)
**File:** dynamic_agent.py, `_track_vuln_found()` (line ~3489)
**Change:** Add scope validation at the top of the method. If target is not in `allowed_targets_set`, `discovered_targets` (when strict expansion), or `target_aliases` values, skip tracking and log warning.
**Risk:** Low. Only adds a guard clause.

### 2. searchsploit Auto-Evidence Save (US-2)
**File:** dynamic_agent.py, `_save_execution()` or `_build_feedback()` area (after execution)
**Change:** After any `searchsploit` command succeeds, auto-write stdout to `{log_dir}/evidence/exploitdb.txt`. Check in `_post_execution()` or the execution save path.
**Risk:** Low. Additive only.

### 3. Recon Completeness Scoring (US-3)
**File:** dynamic_agent.py, new method `_update_recon_checklist()` called from `_update_recon_state()`
**Change:** Track a dict of recon completeness items. Update from execution results. Add signal to context/feedback when complete.
**Risk:** Low. New method + minor integration.

### 4. Target Alias Dedup in Findings (US-4)
**File:** dynamic_agent.py, `_track_vuln_found()` (line ~3489)
**Change:** Before generating vuln_id, resolve target through `target_aliases` to canonical form. Simple dict lookup.
**Risk:** Low. One-liner addition.

### 5. Regex Bug Fix (US-5)
**File:** dynamic_agent.py, line 3432 (in `_pick_vuln_for_command`)
**Change:** Fix `r"(union|or\\s*1=1|sleep\\(|benchmark\\()"` → `r"(union|or\s*1=1|sleep\(|benchmark\()"`. The double-escaped backslashes in a raw string create literal backslash characters instead of regex escapes.
**Risk:** None. Pure bug fix.

## Deployment

1. Edit dynamic_agent.py
2. Verify syntax with `python3 -c "import ast; ..."`
3. `docker compose cp` to both Kali containers
4. Verify syntax inside containers
5. No restart needed — next job launch loads the updated file

## Testing

- Syntax validation (Python AST parse)
- The currently running job (a0ed5aea) won't be affected (already loaded)
- Next job launch will use the improved agent
