# SCM Service Skill

## Overview
Service-first methodology for source control platform discovery and safe configuration review.

## Scope Rules
1. Only operate on explicitly authorized orgs, repos, and tokens.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Avoid modifying repos, issues, or settings unless authorized.
4. Secrets scanning requires explicit authorization.

## Methodology

### 1. Platform Identification
- Identify SCM platform (GitHub, GitLab, Bitbucket, Azure DevOps, Gitea).
- Capture public metadata and version banners where available.

### 2. Inventory (Authorized)
- Enumerate orgs, repos, default branches, and visibility.
- Capture branch protection, required reviewers, and CI hooks.

### 3. Access Validation
- Validate token scopes and least-privilege access.
- Flag tokens with excessive permissions.

### 4. Safe Configuration Review
- Review repository settings for risky defaults (force pushes, missing protections).
- Identify public repositories with sensitive content patterns.

### 5. Explicit-Only Actions
- Secrets scanning, bulk cloning, or content export requires explicit authorization.

## Deep Dives
Load references when needed:
1. GitHub orgs, repo protections, and audit: `references/github.md`
2. GitLab projects, groups, and access controls: `references/gitlab.md`
3. Bitbucket workspaces and repo settings: `references/bitbucket.md`
4. Azure DevOps orgs, repos, and pipelines: `references/azure_devops.md`

## Service-First Workflow (Default)
1. Discovery: platform identification via headers and public endpoints.
2. Inventory: `gh` or `glab` for repo metadata.
3. Access validation: check token scopes and permissions.
4. Explicit-only: `gitleaks` or `trufflehog` for secrets scanning.

## Evidence Collection
1. `scm_inventory.json` with repo metadata and protections (summarized from discovery outputs).
2. `evidence.json` with raw API outputs and access checks.
3. `findings.json` with exposure and misconfiguration evidence.

## Evidence Consolidation
Use `summarize_scm_inventory.py` to consolidate inventory outputs into `scm_inventory.json`.

## Success Criteria
- SCM platform identified and scoped.
- Repo inventory captured safely.
- Misconfigurations documented with evidence.

## Tool References
- ../toolcards/git.md
- ../toolcards/gh.md
- ../toolcards/glab.md
- ../toolcards/gitleaks.md
- ../toolcards/trufflehog.md
- ../toolcards/azure-devops-cli.md
