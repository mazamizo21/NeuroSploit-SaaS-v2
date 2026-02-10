# Spec 007: Recon Phase Improvement

## Context

Analysis of job 5009a4ee (JuiceShop 24h, 1346 iterations, $29.39) revealed that 28.6% of findings were out-of-scope DNS noise, credentials were rediscovered 15+ times due to context trimming, and the agent never transitions cleanly from recon to exploitation. searchsploit output isn't auto-saved, gating Metasploit access.

## User Stories

### US-1: Scope-Validated Finding Submission

**As a** penetration tester reviewing results,
**I want** all findings to be against in-scope targets only,
**So that** my report doesn't contain 192.168.99.* DNS noise or other scope-creep findings.

**Acceptance Criteria:**
- [ ] `_track_vuln_found()` validates target is in `allowed_targets_set` or `discovered_targets` (if scope expansion enabled + strict)
- [ ] Findings against targets not in the resolved scope are logged as `[WARN] SCOPE-FILTERED` and not tracked
- [ ] Docker DNS servers (192.168.99.*, 8.8.8.8, nameservers from /etc/resolv.conf) are never treated as in-scope targets
- [ ] Running the same JuiceShop scenario produces 0 findings on 192.168.99.* IPs

### US-2: searchsploit Auto-Evidence Save

**As a** dynamic agent,
**I want** searchsploit output to be automatically saved to evidence/exploitdb.txt,
**So that** the Metasploit gate (`_has_exploitdb_evidence()`) passes without relying on LLM redirect.

**Acceptance Criteria:**
- [ ] When `searchsploit` command is detected, output is auto-saved to `{evidence_dir}/exploitdb.txt`
- [ ] If exploitdb.txt already exists, new results are appended (not overwritten)
- [ ] `_has_exploitdb_evidence()` returns True after any searchsploit execution
- [ ] msfconsole becomes available after first searchsploit run

### US-3: Recon Completeness Scoring

**As a** dynamic agent,
**I want** to know when recon is "done enough" for a target,
**So that** I transition to exploitation instead of running duplicate nmap/gobuster scans.

**Acceptance Criteria:**
- [ ] Recon checklist tracks: ports_scanned, services_fingerprinted, web_paths_enumerated, tech_identified, dns_resolved
- [ ] Each checklist item is marked complete after a successful relevant command
- [ ] When ≥4/5 items are complete, a `[RECON COMPLETE]` signal is added to the context
- [ ] After recon complete, nmap/gobuster/whatweb commands are tagged as redundant and the agent is reminded to exploit

### US-4: Target Alias Deduplication

**As a** penetration tester,
**I want** findings for `juiceshop` and `172.21.0.12` to be merged,
**So that** the same SQL injection isn't reported twice under different target names.

**Acceptance Criteria:**
- [ ] `_track_vuln_found()` normalizes target using `target_aliases` before generating vuln_id
- [ ] If `172.21.0.12` is an alias for `juiceshop`, vuln_id uses `juiceshop` as canonical
- [ ] Duplicate vuln detection works across hostname and IP variants

### US-5: Fix Regex Pattern Bug

**As a** developer,
**I want** the regex in `_pick_vuln_for_command` to compile correctly,
**So that** exploit attempt tracking doesn't error on every command.

**Acceptance Criteria:**
- [ ] `re.search(r"(union|or\s*1=1|sleep\(|benchmark\()", ...)` compiles without PatternError
- [ ] No `re.PatternError` in any sub-job logs
