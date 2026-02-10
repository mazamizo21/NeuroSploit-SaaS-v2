# vault Toolcard

## Overview
- Summary: Vault CLI manages HashiCorp Vault for secrets and policy operations.

## Advanced Techniques
- Use token policies to validate least-privilege access.
- Prefer metadata listing over secret reads unless authorized.

## Safe Defaults
- Read-only queries by default; avoid secret value reads without explicit authorization.
- Scope to authorized namespaces and mounts.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://developer.hashicorp.com/vault/docs/commands
