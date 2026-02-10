# Sensitive OID Exposure

## Goals
1. Identify exposure of sensitive tables.
2. Record only minimal metadata.
3. Avoid full dumps unless explicitly authorized.

## Examples
- User and process tables
- Routing tables
- Interface MAC addresses

## Safe Checks
1. Use read-only walks with limits.
2. Avoid heavy OIDs unless explicitly authorized.
3. Prefer targeted OIDs for validation.

## Evidence Checklist
1. OID list and counts.
2. Notes on sensitive exposure.
3. Evidence of access control weakness.
