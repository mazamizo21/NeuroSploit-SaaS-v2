# GCP Service Skill

## Overview
Service-first methodology for GCP enumeration, validation, and configuration review with focus on IAM, storage, network, and logging posture.

## Scope Rules
1. Authorized projects only; do not use on unknown tenants.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Prefer read-only queries and least-privilege service accounts.

## Methodology

### 1. Identity and Project Context
- Confirm active account and project using `gcloud auth list` and `gcloud projects list`.
- Record org/folder/project scope and enabled services (read-only).

### 2. Inventory (Authorized)
- Enumerate key services (IAM, storage, compute, networking, Kubernetes).
- Focus on public buckets or overly permissive IAM roles.

### 3. IAM and Service Accounts
- Review IAM bindings, role grants, and service account keys.
- Flag broad roles and long-lived keys.

### 4. Storage and Data Exposure
- Identify public buckets, object ACL exposure, and legacy ACL usage.
- Record sensitive storage paths and ownership controls.

### 5. Network and Compute Exposure
- Review firewall rules, public IP exposure, and load balancer configs.
- Capture risky ports and unrestricted ingress.

### 6. Logging and Monitoring
- Confirm audit logs, log sinks, and alerting coverage.
- Document gaps in monitoring.

### 7. Explicit-Only Actions
- Any exploit or write actions only when explicit authorization is confirmed.

## Service-First Workflow (Default)
1. Discovery: `gcloud` org/project context and enabled services.
2. IAM: bindings, roles, and service account key hygiene.
3. Storage: public access and ACL posture review.
4. Network: firewall rules and public ingress review.
5. Logging: audit log and sink coverage checks.
6. Automated review: `scoutsuite` when authorized for read-only checks.
7. Explicit-only: remediation validation or write actions only when authorized.

## Deep Dives
Load references when needed:
1. Organization and project context: `references/org_project_context.md`
2. Org policy guardrails: `references/org_policies.md`
3. IAM posture: `references/iam_posture.md`
4. IAM role review: `references/iam_roles.md`
5. Storage exposure: `references/storage_exposure.md`
6. Storage public access: `references/storage_public.md`
7. Network exposure: `references/network_exposure.md`
8. Firewall posture: `references/network_firewalls.md`
9. Service account posture: `references/service_accounts.md`
10. Service account keys: `references/service_account_keys.md`
11. Logging and audit: `references/logging_audit.md`

## Evidence Collection
1. `cloud_inventory.json` with project summaries (prefer JSON outputs and summarize).
2. `cloud_identity.json` with org/folder/project context.
3. `cloud_iam.json` with IAM roles and bindings.
4. `cloud_service_accounts.json` with key inventory and posture.
5. `cloud_storage.json` with bucket exposure and ACL posture.
6. `cloud_network.json` with firewall/public ingress findings.
7. `cloud_logging.json` with audit log coverage and sink status.
8. `evidence.json` with raw CLI outputs, account context, and timestamps.
9. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `summarize_gcp_inventory.py` to consolidate JSON outputs into `cloud_inventory.json`.
Summarize IAM, storage, network, and logging evidence into their respective JSON outputs.

## Success Criteria
- Project scope and org context confirmed.
- IAM, storage, network, and logging posture documented.
- High-risk configurations documented with evidence.

## Tool References
- ../toolcards/gcloud.md
- ../toolcards/scoutsuite.md
- ../toolcards/trivy.md
