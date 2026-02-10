# Kubernetes RBAC Posture

## Goals
1. Identify cluster-admin bindings and broad permissions.
2. Capture service accounts with elevated roles.
3. Record bindings to system or default accounts.

## Safe Checks
1. `kubectl get clusterrolebindings -o json`
2. `kubectl get rolebindings -A -o json`

## Indicators to Record
1. `cluster-admin` bindings to service accounts.
2. Wildcard permissions in roles.
3. Bindings to `system:unauthenticated` or `system:authenticated`.

## Evidence Checklist
1. RBAC binding summary.
2. List of high-privilege subjects.
3. Evidence of broad group bindings.
