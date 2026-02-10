# Azure RBAC Posture

## Goals
1. Identify overly permissive role assignments.
2. Confirm administrative roles scope.
3. Record custom roles and wildcard permissions.

## Safe Checks
1. `az role assignment list --all`
2. `az role definition list` (if authorized)

## Indicators to Record
1. Owner/Contributor assignments on subscription scope.
2. Custom roles with wildcard permissions.
3. Role assignments to external guest users.

## Evidence Checklist
1. Role assignment count.
2. Sample high-privilege assignments (redacted).
3. Custom role definitions summary.
