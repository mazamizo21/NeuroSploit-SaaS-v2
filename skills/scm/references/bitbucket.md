# Bitbucket Playbook

## Identification Hints
- Bitbucket exposes REST APIs for repositories and workspace metadata.

## Safe Checks
1. Inventory workspaces and repositories with read-only API calls.
2. Capture branch restrictions and pipeline settings.
3. Validate token scopes for least-privilege.

## Evidence Capture
- Repo visibility, branch restriction settings.
- Auth scope summary and pipeline exposure.

## References
- https://developer.atlassian.com/cloud/bitbucket/rest/
