# AWS IAM Posture

## Goals
1. Identify overly broad IAM policies and risky trust relationships.
2. Confirm MFA enforcement and credential hygiene where visible.
3. Record high-risk policy statements and wildcard usage.

## Safe Checks
1. `aws iam get-account-summary`
2. `aws iam list-roles` and `aws iam list-attached-role-policies` (scoped)
3. `aws iam list-users` (if authorized)
4. `aws iam get-account-authorization-details` (authorized, use sparingly)

## Indicators to Record
1. Admin policies attached to broad roles.
2. Long-lived access keys with no rotation metadata.
3. Roles with wildcard trust policies.
4. Inline policies with `Action: *` or `Resource: *`.

## Evidence Checklist
1. Account summary JSON.
2. Role count and sample policy attachments.
3. Notes on wildcard actions or resources.
4. Trust policy excerpts (redacted).
