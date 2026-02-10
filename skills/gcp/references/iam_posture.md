# GCP IAM Posture

## Goals
1. Identify overly permissive IAM bindings.
2. Confirm role assignments on projects and service accounts.
3. Record conditional bindings and policy versions.

## Safe Checks
1. `gcloud projects get-iam-policy <project> --format=json` (authorized)
2. `gcloud iam roles list` (if authorized)
3. `gcloud organizations get-iam-policy` (if authorized)

## Indicators to Record
1. `roles/owner` or `roles/editor` assigned broadly.
2. Wildcard members such as `allUsers` or `allAuthenticatedUsers`.
3. Roles granted without conditions where expected.

## Evidence Checklist
1. IAM policy bindings summary.
2. High-privilege role assignments.
3. Conditional binding evidence or missing conditions.
