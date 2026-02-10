# AWS Identity and Account Context

## Goals
1. Confirm caller identity, account ID, and active region scope.
2. Record organization/OU context when available.
3. Capture principal type and MFA posture if visible.

## Safe Checks
1. `aws sts get-caller-identity`
2. `aws organizations describe-organization` (if allowed)
3. `aws ec2 describe-regions` (read-only)
4. `aws iam get-account-summary` (if allowed)

## Evidence Checklist
1. Caller ARN, account ID, user/role name.
2. Enabled regions list.
3. Organization ID and master account (if available).
4. MFA device and account MFA status if available.
