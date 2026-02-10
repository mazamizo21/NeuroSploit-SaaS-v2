# Secrets Manager and KMS Posture

## Goals
- Identify Secrets Manager usage and rotation status.
- Review KMS key policies and usage scopes.

## Notes
- Do not retrieve secret values without explicit authorization.
- Record key IDs, rotation status, and key policy exposure.

## Evidence
- Summarize secrets/KMS posture in `cloud_secrets.json`.
- Document high-risk exposures in `findings.json`.
