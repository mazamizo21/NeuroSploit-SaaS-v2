# Azure Key Vault Playbook

## Identification Hints
- Azure Key Vault exposes REST APIs and Azure CLI commands for secrets, keys, and certificates.

## Safe Checks
1. Validate identity with `az account show`.
2. List secret metadata only and capture soft-delete and purge protection settings.
3. Review access policies or RBAC assignments for least-privilege.

## Evidence Capture
- Vault configuration, soft-delete status, and access policy summaries.
- Secret metadata and key usage references.

## References
- https://learn.microsoft.com/azure/key-vault/general/basic-concepts
