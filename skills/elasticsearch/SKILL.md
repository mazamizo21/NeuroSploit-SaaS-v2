# Elasticsearch Service Skill

## Overview
Service-specific methodology for Elasticsearch enumeration and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no data extraction or write operations unless explicit authorization is confirmed.
3. Use read-only endpoints and avoid index modifications.
4. Explicit-only workflows are required for bulk data access or writes (external_exploit=explicit_only).

## Methodology

### 1. Service Fingerprint and Version
- Query the root endpoint for version and cluster metadata.
- Capture headers and server banners.

### 2. Cluster and Index Visibility
- Use read-only APIs to check cluster health and index listings.
- Prefer JSON APIs for automation; use `_cat` for human-readable views.

### 3. Access and Security Validation
- Identify whether authentication is required.
- Flag open clusters or exposed sensitive indices.

## Service-First Workflow (Default)
1. Discovery: fingerprint version and cluster metadata via `curl` or `httpx`.
2. Visibility checks: read-only APIs for cluster health and index listings.
3. Access validation: confirm auth requirements and exposed metadata only.
4. Explicit-only data access: any document retrieval or write operations only when authorization is confirmed.

## Deep Dives
Load references when needed:
1. Cluster health evidence: `references/cluster_health.md`
2. Security posture checks: `references/security_posture.md`
3. Index exposure risks: `references/index_risks.md`

## Evidence Collection
1. `es_cluster.json` with version and cluster metadata.
2. `es_indices.json` with index visibility.
3. `evidence.json` with raw cluster and index outputs.
4. `findings.json` with exposure or security risks.

## Evidence Consolidation
Use `summarize_es.py` to consolidate cluster and index JSON into `es_cluster.json`.

## Success Criteria
- Elasticsearch version and cluster metadata captured.
- Index visibility and access controls documented.
- Risky exposure documented with evidence.

## Tool References
- ../toolcards/elasticsearch.md
- ../toolcards/httpx.md
- ../toolcards/curl.md
