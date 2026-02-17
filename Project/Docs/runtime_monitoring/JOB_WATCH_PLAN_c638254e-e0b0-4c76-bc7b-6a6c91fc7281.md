# Job Watch Plan — c638254e-e0b0-4c76-bc7b-6a6c91fc7281

## Objectives
- Continuous monitoring: recent logs, loop detection, findings/vuln tracker state, stall detection, worker health, container health.
- Verify correct behavior across phases: Recon → Vuln Scan → Exploit → Access → Persist → Lateral Move → Privesc → Exfiltrate.
- Archive every snapshot and remediation output under `Project/Docs/runtime_monitoring/<timestamp>_job_<job_id>/`.

## Current Known Signals (as of 2026-02-17)
- Job is running in `tazosploit-kali-1` (Redis key `job:<id>:kali_container_name`).
- `structured_findings.json`: 2 findings, both exploited.
- Redis `job:<id>:live_stats` exists (hash) and shows iteration ~71/2000 and vulnerabilities=2.
- Supervisor is disabled for this job (`job:<id>:supervisor_enabled=false` and DB `supervisor_enabled=f`).

## Watch Checklist (repeat every 1–3 minutes)
1. **Agent health / stall**
   - `dynamic_agent.log` mtime age < 120s.
   - Iteration increases over time.
2. **Loop / scan-loop**
   - Look for repeated commands or repeating enumeration blocks.
   - Check for `REJECTED scan-with-unexploited-findings` and `BLOCKED post-recon scan` events.
3. **Findings/Vuln tracker sanity**
   - `structured_findings.json` count, exploited/unexploited.
   - `vuln_tracker.json` keys and exploited flags.
   - Redis `live_stats` matches the above.
4. **Phase progression evidence**
   - Recon evidence: ports/services enumerated artifacts.
   - Vuln scan evidence: nikto/nuclei/sqlmap outputs.
   - Exploit/access evidence: JWT/admin tokens, authenticated endpoint access.
   - Persist/lateral/privesc: only if policy allows (see job policy flags).
   - Exfiltrate: DB dumps, sensitive files downloaded.
5. **Infra health**
   - `docker compose ps` healthy.
   - `docker stats --no-stream` resource pressure within limits.

## Known Engineering Gaps to Remediate
- `_detect_tool()` regex in `kali-executor/open-interpreter/dynamic_agent.py` is over-escaped (`[\\s...]`), causing tool detection to fail and `tool_used` to become `#`/`cd`. This breaks tool usage tracking, recon checklist completion, and phase nudges.
- `save_session()` omits phase/recon fields, so the session JSON does not show phase progression.
- Job policy flags: DB shows `allow_persistence=false` (persistence attempts are blocked), so full phase progression to Persist may be impossible without reconfig/restart.

## Remediation Approach
- Patch code in-repo (dynamic_agent.py) to fix `_detect_tool()` and `save_session()`.
- Rebuild/restart affected service/job if necessary (with logs captured before/after).
