# Credential Access Skill

## Overview
Validate credential exposure and document evidence with minimal collection and strong redaction.

## Scope Rules
1. Only operate on explicitly in-scope hosts, apps, and data sources.
2. External targets: credential extraction requires explicit authorization (external_exploit=explicit_only).
3. Prefer offline analysis and avoid online guessing unless explicitly authorized.
4. Redact secrets in reports; store raw data only in approved evidence storage.

## Methodology

### 1. Credential Discovery
- Identify credential storage locations and types.
- Capture metadata and minimal proof of exposure.

### 2. Windows Sources (Authorized)
- Validate exposure of LSASS, registry hives, or DPAPI-protected secrets.
- Capture evidence without persistence or disruption.

### 3. Linux Sources (Authorized)
- Identify sensitive files and history artifacts.
- Record minimal proof and avoid broad data collection.

### 4. Application and Browser Stores
- Identify app config secrets or browser stores.
- Redact tokens and cookies.

### 5. Offline Cracking (Explicit-Only)
- Use authorized hash sets only.
- Prefer `--show` outputs to capture minimal evidence.

## Deep Dives
Load references when needed:
1. Scope and authorization: `references/scope_authorization.md`
2. Windows sources: `references/windows_sources.md`
3. Linux sources: `references/linux_sources.md`
4. Browser stores: `references/browser_stores.md`
5. Offline cracking: `references/cracking_offline.md`
6. Redaction guidance: `references/redaction.md`

## Evidence Collection
1. `credentials.json` (in evidence/) with structured fields:
   - `username`, `password` (redacted in report), `host`, `port`, `protocol`, `service`, `verified`
2. `creds.json` with redacted evidence and counts.
3. `evidence.json` with source metadata and proof points.
4. `findings.json` with exposure impact notes.

## Evidence Consolidation
Use `parse_hashcat_show.py` to summarize offline cracking outputs into `creds.json`.

## Success Criteria
- Credential exposure identified and scoped.
- Evidence captured with redaction.
- No unauthorized credential collection performed.
