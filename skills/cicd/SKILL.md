# CI/CD Service Skill

## Overview
Service-first methodology for CI/CD platform discovery and safe configuration review.

## Scope Rules
1. Only operate on explicitly authorized CI/CD platforms, repos, and tokens.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Avoid triggering builds or modifying pipelines unless authorized.
4. Use rate limits for API or web scanning.

## Methodology

### 1. Discovery and Fingerprinting
- Identify CI/CD platforms (Jenkins, GitLab CI, GitHub Actions, Azure DevOps, etc.).
- Capture version banners, exposed endpoints, and public metadata.

### 2. Access Validation
- Use provided tokens or credentials only.
- Record authentication success or failure once per platform.

### 3. Safe Configuration Review
- Review pipeline definitions for risky patterns (secrets in logs, unsigned artifacts).
- Enumerate runners/agents and their scopes.

### 4. Secrets and Artifact Exposure (Authorized)
- Scan authorized repos for embedded secrets or credentials.
- Review artifact retention and access controls.

### 5. Explicit-Only Actions
- Triggering builds, modifying jobs, or uploading artifacts requires explicit authorization.

## Service-First Workflow (Default)
1. Discovery: `httpx` and `nuclei` for platform fingerprinting.
2. Safe review: read-only API checks for job, runner, and artifact metadata.
3. Authorized secrets scan: `gitleaks` on in-scope repositories.
4. Explicit-only: build triggers or pipeline modification.

## Deep Dives
Load references when needed:
1. Platform fingerprints: `references/platform_fingerprints.md`
2. Pipeline risk patterns: `references/pipeline_risks.md`
3. Runner posture: `references/runner_posture.md`
4. Secrets exposure checks: `references/secrets_exposure.md`

## Evidence Collection
1. `cicd_inventory.json` with platform versions and runner metadata (summarize discovery outputs).
2. `evidence.json` with raw discovery outputs and scan summaries.
3. `findings.json` with exposure and misconfiguration evidence.

## Evidence Consolidation
Use `summarize_cicd_inventory.py` to consolidate HTTP, nuclei, and secrets scan outputs into `cicd_inventory.json`.

## Success Criteria
- CI/CD platform identified and scoped.
- Risky configurations documented with evidence.
- Actions constrained to authorized repositories.

## Tool References
- ../toolcards/httpx.md
- ../toolcards/nuclei.md
- ../toolcards/trivy.md
- ../toolcards/gitleaks.md
- ../toolcards/nmap.md
