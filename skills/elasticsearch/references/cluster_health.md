# Cluster Health and Version Evidence

## Goals
- Identify cluster name, version, and node counts.
- Capture health status without modifying indices.

## Safe Checks
- `GET /` for version metadata
- `GET /_cluster/health`
- `GET /_nodes` (if authorized, metadata only)

## Evidence Checklist
- Cluster name and version
- Health status and node counts
- Any red/yellow status causes (if visible)

