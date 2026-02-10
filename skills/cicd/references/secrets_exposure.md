# Secrets Exposure Checks

## Goals
1. Identify leaked secrets in authorized repos or build logs.
2. Reduce false positives with scoping and redaction.
3. Record secret types and impacted scopes.

## Safe Checks
1. `gitleaks detect --redact` on authorized repos.
2. `trivy repo --scanners secret` when approved.

## Indicators to Record
1. Secret type and file path (redacted).
2. Commit metadata (hash only).
3. Secret scope and potential impact notes.

## Evidence Checklist
1. Secrets scan summary.
2. Redacted sample findings.
3. Note of repositories and branches scanned.
