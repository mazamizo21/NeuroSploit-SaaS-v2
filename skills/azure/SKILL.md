# Azure Service Skill

## Overview
Service-first methodology for Azure enumeration, validation, and configuration review with focus on RBAC, storage, network, and logging posture.

## Scope Rules
1. Authorized tenants only; do not use on unknown tenants.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Prefer read-only queries and least-privilege service principals.

## Methodology

### 1. Identity and Subscription Context
- Confirm tenant and subscription identity with `az account show`.
- Record active subscriptions, management groups, and regions (read-only).

### 2. Inventory (Authorized)
- Enumerate key services (Entra ID roles, RBAC, storage accounts, key vaults, VMs, networking).
- Focus on publicly exposed resources or overly permissive roles.

### 3. RBAC and Identity Posture
- Review RBAC assignments, role scopes, and privileged role holders.
- Flag broad role assignments and stale identities.

### 4. Storage and Key Vault Exposure
- Identify public storage containers, SAS tokens, and overly permissive access.
- Review Key Vault access policies and secret management posture.

### 5. Network and Compute Exposure
- Review NSGs, public IP exposure, and risky inbound rules.
- Capture exposed management ports and unrestricted sources.

### 6. Logging and Monitoring
- Confirm activity log, diagnostic settings, and Defender coverage.
- Document gaps in logging or alerting.

### 7. Explicit-Only Actions
- Any exploit or write actions only when explicit authorization is confirmed.

## Service-First Workflow (Default)
1. Discovery: `azure-cli` tenant/subscription context.
2. Identity: Entra ID roles and RBAC posture review.
3. Storage: public access and SAS token exposure review.
4. Key Vault: access policy and secret management posture.
5. Network: NSG rules and public ingress review.
6. Logging: activity/diagnostic logs and Defender status checks.
7. Automated review: `scoutsuite` when authorized for read-only checks.
8. Explicit-only: remediation validation or write actions only when authorized.

## Deep Dives
Load references when needed:
1. Tenant and subscription context: `references/tenant_context.md`
2. Entra ID roles: `references/entra_roles.md`
3. RBAC posture: `references/rbac_posture.md`
4. RBAC assignments: `references/rbac_assignments.md`
5. Storage exposure: `references/storage_exposure.md`
6. SAS token posture: `references/storage_sas.md`
7. Key Vault posture: `references/keyvault_posture.md`
8. Key Vault access review: `references/keyvault_access.md`
9. Network exposure: `references/network_exposure.md`
10. Network security posture: `references/network_security.md`
11. Logging and monitoring: `references/logging_monitoring.md`

## Evidence Collection
1. `cloud_inventory.json` with tenant/subscription summaries (prefer JSON outputs and summarize).
2. `cloud_identity.json` with tenant, subscription, and role context.
3. `cloud_rbac.json` with role assignments and privilege posture.
4. `cloud_storage.json` with public access and SAS posture.
5. `cloud_keyvault.json` with access policy posture.
6. `cloud_network.json` with NSG/public ingress findings.
7. `cloud_logging.json` with activity/diagnostic log coverage.
8. `evidence.json` with raw CLI outputs, account context, and timestamps.
9. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `summarize_azure_inventory.py` to consolidate JSON outputs into `cloud_inventory.json`.
Summarize RBAC, storage, network, and logging evidence into their respective JSON outputs.

## Success Criteria
- Tenant scope and subscription context confirmed.
- RBAC, storage, network, and logging posture documented.
- High-risk configurations documented with evidence.

## Tool References
- ../toolcards/azure-cli.md
- ../toolcards/scoutsuite.md
- ../toolcards/trivy.md
