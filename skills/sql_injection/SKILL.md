# SQL Injection Skill

## Overview
Service-first methodology for validating SQL injection safely and capturing minimal proof of impact.

## Scope Rules
1. Only operate on explicitly in-scope applications and parameters.
2. External targets: exploitation or data extraction requires explicit authorization (external_exploit=explicit_only).
3. Prefer read-only queries and minimal data extraction.
4. Avoid stacked queries, file operations, or OS shells unless explicitly authorized.

## Methodology

### 1. Detection and Validation
- Identify injection points using low-impact payloads.
- Record parameter, method, and response behavior.

### 2. DBMS Fingerprinting
- Use error messages or safe version queries to identify DBMS.
- Avoid heavy union queries on external targets.

### 3. Minimal Proof of Impact
- Enumerate database name and table list only.
- Extract a single non-sensitive row if approved.

### 4. Explicit-Only Advanced Actions
- Data dumps, file read/write, OS command execution, or WAF bypasses require explicit authorization.

## Deep Dives
Load references when needed:
1. Detection and validation: `references/detection_validation.md`
2. Safe payloads: `references/safe_payloads.md`
3. DBMS fingerprinting: `references/dbms_fingerprinting.md`
4. Minimal data extraction: `references/data_extraction.md`
5. Explicit-only advanced actions: `references/explicit_only_advanced.md`

## Evidence Collection
1. `evidence.json` with parameter, method, DBMS, and injection type (parse sqlmap logs if used).
2. `findings.json` with validated impact and redacted proof.
3. `creds.json` only when explicitly authorized and redacted.

## Evidence Consolidation
Use `parse_sqlmap_log.py` to convert sqlmap logs into `evidence.json`.

## Success Criteria
- SQL injection confirmed with safe payloads.
- DBMS identified with evidence.
- Minimal proof of impact captured without data modification.
