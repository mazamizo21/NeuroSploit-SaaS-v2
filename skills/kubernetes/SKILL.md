# Kubernetes Service Skill

## Overview
Service-first methodology for Kubernetes control plane discovery and safe configuration review.

## Scope Rules
1. Only operate on explicitly authorized clusters and kubeconfigs.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Prefer read-only API calls; avoid creating or modifying resources.
4. Do not execute commands in pods unless explicitly authorized.

## Methodology

### 1. Discovery and API Access
- Identify API server endpoints and versions.
- Validate access with provided kubeconfig or token.

### 2. Inventory (Authorized)
- Enumerate namespaces, nodes, and workloads.
- Capture RBAC bindings and service accounts.

### 3. Configuration Review
- Check for anonymous access, overly permissive roles, or public dashboards.
- Validate network policies and secrets exposure patterns.

### 4. Explicit-Only Actions
- Pod exec, privilege escalation, or resource creation requires explicit authorization.

## Deep Dives
Load references when needed:
1. API access validation: `references/api_access.md`
2. RBAC posture: `references/rbac_posture.md`
3. Workload exposure: `references/workload_exposure.md`
4. Security controls: `references/security_controls.md`

## Service-First Workflow (Default)
1. Discovery: `nmap` to identify API servers.
2. Access validation: `kubectl` read-only inventory.
3. Automated review: `kube-bench` for CIS checks.
4. Explicit-only: `kube-hunter` active testing and any write operations.

## Evidence Collection
1. `k8s_inventory.json` with namespaces, nodes, RBAC summary (summarized from `kubectl` JSON).
2. `evidence.json` with raw `kubectl` outputs and cluster context.
3. `findings.json` with misconfigurations or exposure evidence.

## Evidence Consolidation
Use `summarize_k8s_inventory.py` to consolidate JSON outputs into `k8s_inventory.json`.

## Success Criteria
- API access scope confirmed.
- Inventory captured safely.
- High-risk configurations documented with evidence.

## Tool References
- ../toolcards/kubectl.md
- ../toolcards/kube-bench.md
- ../toolcards/kube-hunter.md
- ../toolcards/nmap.md
