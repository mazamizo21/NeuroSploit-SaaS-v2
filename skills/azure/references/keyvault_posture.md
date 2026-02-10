# Azure Key Vault Posture

## Goals
1. Identify exposed vaults and access policies.
2. Confirm soft-delete and purge protection.
3. Record RBAC vs access policy mode and logging posture.

## Safe Checks
1. `az keyvault list`
2. `az keyvault show --name <vault>` (authorized)
3. `az keyvault secret list --vault-name <vault>` (authorized, metadata only)

## Indicators to Record
1. Public network access enabled.
2. Soft delete or purge protection disabled.
3. Broad access policies.
4. Vault firewall disabled for sensitive vaults.

## Evidence Checklist
1. Vault list with regions.
2. Access policy summaries.
3. Firewall and protection settings evidence.
