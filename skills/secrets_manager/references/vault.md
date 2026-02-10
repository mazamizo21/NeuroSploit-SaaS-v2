# Vault Playbook

## Identification Hints
- HashiCorp Vault exposes HTTP APIs and supports namespaces and mounts.

## Safe Checks
1. Validate identity and token policies with read-only commands.
2. List mounts and secret metadata only.
3. Confirm audit logging is enabled.

## Evidence Capture
- Mounts, auth methods, and policy summaries.
- Audit logging status and token scope.

## References
- https://developer.hashicorp.com/vault/docs/commands
