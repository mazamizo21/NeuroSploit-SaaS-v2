# Index Exposure Risks

## Goals
- Identify public indices and sensitive fields without bulk extraction.
- Capture index metadata at a high level only.

## Safe Checks
- `_cat/indices?format=json`
- `_cat/aliases?format=json`
- `_mapping` metadata for index names (avoid full field dumps if not authorized)

## Indicators
- Indices with sensitive naming patterns (users, auth, secrets, logs)
- Large document counts on public clusters

## Evidence Checklist
- Index list and counts
- Alias mappings
- Notes on sensitive naming patterns

