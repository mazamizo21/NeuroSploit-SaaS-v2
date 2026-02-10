# MongoDB Service Skill

## Overview
Service-first methodology for MongoDB enumeration and safe configuration validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and databases.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Prefer read-only queries and avoid data modification.
4. Do not perform credential guessing without explicit authorization.

## Methodology

### 1. Discovery and Versioning
- Identify MongoDB services on TCP 27017 and related ports.
- Capture build and wire protocol versions where available.

### 2. Access Validation
- Use provided credentials only.
- Record authentication success or failure once per host.

### 3. Safe Enumeration (Authorized)
- List databases, collections, and roles using read-only commands.
- Capture server parameters relevant to security (auth enabled, bind IP).

### 4. Risky Exposure Checks
- Detect unauthenticated access.
- Flag overly permissive roles or exposed admin interfaces.

## Deep Dives
Load references when needed:
1. Authentication posture: `references/auth_posture.md`
2. Roles and privileges: `references/role_review.md`
3. Configuration exposure: `references/config_exposure.md`

## Service-First Workflow (Default)
1. Discovery: `nmap` MongoDB scripts for version and info.
2. Access validation: `mongosh` read-only queries.
3. Authorized enrichment: metadata inventory (db/collection/role summaries).
4. Explicit-only: `mongodump` data exports or NoSQL injection testing.

## Evidence Collection
1. `mongodb_inventory.json` with versions, databases, and role summaries (summarized from JSON outputs).
2. `evidence.json` with raw shell outputs and connection metadata.
3. `findings.json` with exposure or auth issues.

## Evidence Consolidation
Use `summarize_mongo_inventory.py` to consolidate JSON outputs into `mongodb_inventory.json`.

## Success Criteria
- MongoDB version and access level confirmed.
- Databases and roles enumerated safely.
- Misconfigurations documented with evidence.

## Tool References
- ../toolcards/mongosh.md
- ../toolcards/mongodump.md
- ../toolcards/nosqlmap.md
- ../toolcards/nmap.md
