# Secrets Manager Service Skill

## Overview
Service-first methodology for secrets manager discovery and safe configuration validation.

## Scope Rules
1. Only operate on explicitly authorized accounts and vaults.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. List and metadata access is allowed; secret value retrieval requires explicit authorization.
4. Avoid mass export or bulk reads unless authorized.

## Methodology

### 1. Identity and Context
- Confirm caller identity and account scope.
- Identify provider (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).

### 2. Inventory (Authorized)
- Enumerate secret names, versions, and tags (metadata only).
- Record key management settings and access policies.

### 3. Hardening Checks
- Verify secret rotation settings and expiration policies.
- Confirm audit logging and access monitoring are enabled.
- Validate least-privilege policies and deny overly broad access.

### 4. Policy Diff Automation
- Use `policy_diff.py` to compare policy or ACL snapshots before and after changes.
- Store diff output as `policy_diff.json` in evidence.

### 5. Explicit-Only Actions
- Secret value reads, exports, or rotations require explicit authorization.

## Deep Dives
Load references when needed:
1. Vault policies and audit posture: `references/vault.md`
2. AWS Secrets Manager rotation and access: `references/aws_secrets_manager.md`
3. Azure Key Vault access policies and logging: `references/azure_key_vault.md`
4. GCP Secret Manager IAM and rotation: `references/gcp_secret_manager.md`

## Service-First Workflow (Default)
1. Discovery: provider CLI to validate identity and scope.
2. Inventory: metadata listing for secrets and policies.
3. Safe review: assess access policies and audit logging.
4. Explicit-only: secret value retrieval or export.

## Evidence Collection
1. `secrets_inventory.json` with secret metadata and policy summaries.
2. `policy_diff.json` for before/after policy comparisons.
3. `evidence.json` with raw policy outputs and inventory notes.
4. `findings.json` with misconfiguration evidence.

## Evidence Consolidation
Use `policy_diff.py` to generate `policy_diff.json` from policy snapshots.

## Success Criteria
- Provider and account scope confirmed.
- Secret metadata inventoried safely.
- Risky access documented with evidence.

## Tool References
- ../toolcards/vault.md
- ../toolcards/awscli.md
- ../toolcards/azure-cli.md
- ../toolcards/gcloud.md
