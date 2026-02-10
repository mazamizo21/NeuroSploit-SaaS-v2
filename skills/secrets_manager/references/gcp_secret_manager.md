# GCP Secret Manager Playbook

## Identification Hints
- GCP Secret Manager exposes REST APIs and gcloud CLI for secrets and versions.

## Safe Checks
1. Validate identity with `gcloud auth list` and project scope.
2. List secret metadata only and capture replication settings.
3. Review IAM bindings for least-privilege access.

## Evidence Capture
- Secret metadata, replication policy, and IAM summaries.

## References
- https://cloud.google.com/secret-manager/docs
