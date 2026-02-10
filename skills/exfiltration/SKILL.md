# Data Access Validation Skill

## Overview
Validate data exposure with minimal collection to prove impact, prioritizing data minimization and redaction.

## Scope Rules
1. Only operate on explicitly authorized data sources.
2. External targets: bulk exports require explicit authorization (external_exploit=explicit_only).
3. Capture minimal samples and redact sensitive data.

## Methodology

### 1. Identify Sensitive Data Sources
- Locate high-risk data sources (files, databases, object storage, shares).
- Confirm access with metadata where possible.

### 2. Minimize Data Collected
- Capture minimal samples only (headers, row counts, metadata).
- Redact PII and secrets in evidence.

### 3. Evidence Packaging (Authorized)
- If evidence requires packaging, use local, temporary archives.
- Do not transfer data out of scope without explicit authorization.

### 4. Explicit-Only Exfiltration
- Any bulk export or transfer requires explicit authorization.

## Deep Dives
Load references when needed:
1. Data minimization: `references/data_minimization.md`
2. Sensitive sources: `references/sensitive_sources.md`
3. Database sources: `references/database_sources.md`
4. File shares and SMB: `references/file_shares.md`
5. Object storage sources: `references/object_storage.md`
6. Packaging and compression: `references/packaging.md`
7. Transfer controls: `references/transfer_controls.md`
8. Redaction guidelines: `references/redaction_guidelines.md`
9. Explicit-only exfiltration: `references/explicit_only_exfil.md`

## Evidence Collection
1. `data_access.json` with access validation and scope references.
2. `data_sources.json` with sources, owners, and exposure notes.
3. `redaction_log.json` with redaction steps and sample hashes.
4. `evidence.json` with redacted sample proof.
5. `findings.json` with impact notes and scope references.

## Evidence Consolidation
Use `redact_samples.py` to redact minimal samples before storing them in `evidence.json`.
Summarize data sources and redaction steps into `data_sources.json` and `redaction_log.json`.

## Success Criteria
- Data exposure validated without excess collection.
- Sources and redaction steps documented with evidence.
