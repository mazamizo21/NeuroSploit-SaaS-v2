# azure-cli Toolcard

## Overview
- Summary: The Azure CLI is a cross-platform command-line tool for managing Azure resources.

## Advanced Techniques
- Use least-privilege service principals and read-only queries.
- Segment subscriptions and resource groups for scoped checks.

## Safe Defaults
- Authorized accounts only; do not use on unknown tenants.
- Avoid write or delete actions unless explicitly authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://learn.microsoft.com/en-us/cli/azure/
