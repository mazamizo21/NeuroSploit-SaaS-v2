# Tasks: 007 Recon Phase Improvement

## Task 1: Fix Regex Bug in _pick_vuln_for_command [US-5]
- [ ] Find line with `r"(union|or\\s*1=1|sleep\\(|benchmark\\()"` (around line 3432)
- [ ] Replace with `r"(union|or\s*1=1|sleep\(|benchmark\()"` 
- [ ] Verify no other broken regex patterns

## Task 2: Add Scope Validation to _track_vuln_found [US-1, US-4]
- [ ] At top of `_track_vuln_found()`, resolve target through `target_aliases` to canonical
- [ ] Check if resolved target is in `allowed_targets_set` or valid discovered target
- [ ] If not in scope, log `[WARN] SCOPE-FILTERED: {vuln_type} on {target}` and return early
- [ ] Skip scope check for "localhost" findings (database access etc.) since those are self-referential

## Task 3: Auto-Save searchsploit Output [US-2]
- [ ] In `_save_execution()` or post-execution path, detect `searchsploit` tool
- [ ] If execution succeeded and has stdout, write to `{log_dir}/evidence/exploitdb.txt`
- [ ] Use append mode if file exists, write mode if not
- [ ] Create evidence directory if it doesn't exist

## Task 4: Implement Recon Completeness Scoring [US-3]
- [ ] Add `self.recon_checklist` dict in `__init__`: {ports_scanned, services_fingerprinted, web_paths_enumerated, tech_identified, exploitdb_checked}
- [ ] Add `_update_recon_checklist()` method called from `_update_recon_state()` and `_save_execution()`
- [ ] Mark items complete based on tool used (nmap→ports, gobuster/ffuf→web_paths, whatweb/nikto→tech, searchsploit→exploitdb)
- [ ] When ≥4/5 complete, set `self.recon_phase_complete = True`
- [ ] In `_build_feedback()`, add hint when recon is complete: "⚡ RECON COMPLETE: Move to exploitation"
- [ ] In context building, add recon status when incomplete: list remaining items

## Task 5: Deploy and Verify
- [ ] Run Python syntax check on modified file
- [ ] Copy to both Kali containers
- [ ] Verify syntax inside containers
