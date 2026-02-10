# AWS Secrets Manager Playbook

## Identification Hints
- AWS Secrets Manager is accessed via AWS APIs and CLI.

## Safe Checks
1. Validate identity with `aws sts get-caller-identity`.
2. List secrets metadata only and capture rotation status.
3. Review resource policies and KMS key usage for least-privilege.

## Evidence Capture
- Secret metadata, rotation configuration, and policy summaries.
- KMS key references and access boundaries.

## References
- https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html
