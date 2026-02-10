# Spec 003: Finding Deduplication

## Problem Statement

The Dynamic Agent can report the same vulnerability multiple times across iterations, especially when:
- It re-runs a scan tool that produces the same output
- It validates a vuln through different techniques (curl + sqlmap) producing separate findings
- The worker's `_normalize_findings()` and `_post_findings_and_loot()` don't check for existing findings before inserting

This leads to inflated finding counts on the dashboard, misleading severity breakdowns, and cluttered reports.

### Example
A single SQL injection on `/rest/products/search?q=` might appear as:
1. "SQL Injection — /rest/products/search" (from initial curl test)
2. "SQLi vulnerability at /rest/products/search?q=" (from sqlmap confirmation)
3. "SQL Injection (T1190) at /rest/products/search" (from vuln tracker memory)

## Proposed Solution

### 1. Dedup Key Generation

Define a canonical dedup key for each finding based on:
- Normalized target (hostname only, no port/path scheme variations)
- Finding type (normalized: "sql_injection", "xss", "lfi", etc.)
- Location (URL path, stripped of query parameters)

```python
def _dedup_key(finding: dict) -> str:
    import hashlib
    target = _normalize_target(finding.get("target", ""))
    ftype = _normalize_finding_type(finding.get("finding_type") or finding.get("type", ""))
    location = _normalize_location(finding.get("location") or _extract_path(finding.get("target", "")))
    raw = f"{target}|{ftype}|{location}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

### 2. Worker-Side Dedup Before API Post

In `_post_findings_and_loot()`, maintain a set of posted dedup keys:

```python
async def _post_findings_and_loot(self, ...):
    posted_keys = set()
    for finding in normalized_findings:
        key = self._dedup_key(finding)
        if key in posted_keys:
            logger.debug("finding_deduplicated", key=key, title=finding.get("title"))
            continue
        posted_keys.add(key)
        # Post to API...
```

### 3. Database-Level Dedup Constraint

Add a unique constraint on findings:
```sql
ALTER TABLE findings ADD COLUMN dedup_key VARCHAR(16);
CREATE UNIQUE INDEX idx_findings_dedup ON findings(job_id, dedup_key) WHERE dedup_key IS NOT NULL;
```

This prevents duplicates even if the worker fails to dedup (e.g., restart mid-post).

### 4. Merge Strategy for Duplicates

When a duplicate is detected, **merge** rather than discard:
- Keep the higher severity
- Append evidence from the newer finding
- Keep the more specific MITRE technique
- Update `tool_used` to include both tools

### 5. Agent-Side Memory Dedup

The Dynamic Agent already has `vulns_found` dict. Extend it to emit a dedup hint:
```python
# In _update_vuln_tracker():
self.vulns_found[vuln_id] = {
    "dedup_key": self._compute_dedup_key(vuln_type, target),
    ...
}
```

## Acceptance Criteria
- [ ] Same vulnerability on same target/location is reported only once per job
- [ ] Dashboard finding counts accurately reflect unique vulnerabilities
- [ ] Evidence from multiple detections is merged into a single finding
- [ ] Reports show "Detected by: nmap, sqlmap" for multi-tool detections
- [ ] Database constraint prevents duplicates even on worker crash/restart

## Files to Modify
- `execution-plane/worker/main.py` — Add dedup logic in `_post_findings_and_loot()`
- `control-plane/api/routers/jobs.py` — Handle dedup constraint violations gracefully
- `control-plane/db/init.sql` — Add dedup_key column and unique index
- `control-plane/api/models.py` — Add dedup_key to Finding model
- `kali-executor/open-interpreter/dynamic_agent.py` — Add dedup key computation

## Risk Assessment
- **Low**: Dedup is additive; existing findings are unaffected
- **Medium**: Merge strategy needs careful ordering to avoid losing evidence
