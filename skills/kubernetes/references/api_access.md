# Kubernetes API Access

## Goals
1. Confirm API server version and access level.
2. Validate that credentials are scoped correctly.
3. Record cluster endpoint and authentication type.

## Safe Checks
1. `kubectl version --short`
2. `kubectl auth can-i --list` (read-only)
3. `kubectl cluster-info` (read-only)

## Indicators to Record
1. Anonymous access enabled.
2. Cluster-admin permissions on broad subjects.
3. API server exposed publicly without restrictions.

## Evidence Checklist
1. API version and server endpoint.
2. Access review summary.
3. Cluster-info output and authentication notes.
