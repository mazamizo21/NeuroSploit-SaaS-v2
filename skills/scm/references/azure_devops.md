# Azure DevOps Playbook

## Identification Hints
- Azure DevOps exposes REST APIs for organizations, projects, repos, and pipelines.

## Safe Checks
1. Inventory projects and repos using read-only queries.
2. Capture branch policies, build pipeline permissions, and artifact visibility.
3. Validate token scopes and PAT permissions for least-privilege.

## Evidence Capture
- Project visibility, branch policies, pipeline exposure.
- Auth scope summary and audit logging settings.

## References
- https://github.com/Azure/azure-devops-cli-extension
