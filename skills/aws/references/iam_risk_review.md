# IAM Risk Review

## Goals
- Identify over-privileged roles and risky trust relationships.
- Flag broad permissions (`*:*`, `iam:PassRole`, admin policies).

## Notes
- Do not modify policies.
- Record role names, policy ARNs, and trust principals.

## Evidence
- Summarize IAM risk in `cloud_iam.json` and `findings.json`.
