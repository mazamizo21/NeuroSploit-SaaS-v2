# AWS Service Skill

## Overview
Service-first methodology for AWS enumeration, validation, and configuration review with an emphasis on identity, storage, network, and logging posture.

## Scope Rules
1. Authorized accounts only; do not use on unknown tenants.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Prefer read-only queries and least-privilege roles.

## Methodology

### 1. Identity and Account Context
- Confirm caller identity and account scope using `aws sts get-caller-identity`.
- Record org/account structure, enabled regions, and key metadata (read-only).

### 2. Inventory (Authorized)
- Enumerate key services (IAM, S3, EC2, RDS, ECR, KMS) with read-only calls.
- Focus on publicly exposed resources or overly permissive policies.

### 3. IAM and Access Posture
- Review IAM policies, role trust relationships, and access key hygiene.
- Flag privilege escalation paths and unused/over-privileged roles.

### 4. Storage and Data Exposure
- Identify public buckets, object ACL exposure, and missing public access blocks.
- Note sensitive data paths and ownership controls.

### 5. Network and Compute Exposure
- Review security groups, NACLs, public IP assignments, and IMDS posture.
- Record instances with public ingress and risky port exposure.

### 6. Logging and Monitoring
- Confirm CloudTrail, Config, GuardDuty, and Security Hub coverage.
- Document gaps in audit logging and alerting.

### 7. Explicit-Only Actions
- Any exploit or write actions only when explicit authorization is confirmed.

## Service-First Workflow (Default)
1. Discovery: `awscli` account context and enabled regions.
2. Identity: IAM roles, policies, and access key hygiene review.
3. Storage: S3 exposure and public access block validation.
4. Network: SG/NACL reviews, public ingress, and IMDS posture.
5. Logging: CloudTrail/Config/GuardDuty status checks.
6. Automated review: `prowler` and `scoutsuite` for read-only checks.
7. Explicit-only: remediation validation or write actions only when authorized.

## Deep Dives
Load references when needed:
1. Identity and account context: `references/identity_context.md`
2. Organization structure and regions: `references/org_structure.md`
3. IAM posture review: `references/iam_posture.md`
4. IAM risk review: `references/iam_risk_review.md`
5. S3 exposure checks: `references/s3_exposure.md`
6. Public access block review: `references/s3_public_access_block.md`
7. Network exposure checks: `references/network_exposure.md`
8. Security groups and NACLs: `references/network_security_groups.md`
9. EC2 metadata posture: `references/ec2_metadata.md`
10. Logging and monitoring: `references/logging_monitoring.md`
11. Security guardrails: `references/logging_guardrails.md`
12. Secrets and KMS posture: `references/secrets_kms.md`

## Evidence Collection
1. `cloud_inventory.json` with account/service summaries (prefer JSON outputs and summarize).
2. `cloud_identity.json` with account, org, and role context.
3. `cloud_iam.json` with role/policy highlights and access key hygiene.
4. `cloud_storage.json` with S3 exposure and public access block status.
5. `cloud_network.json` with SG/NACL/public ingress findings.
6. `cloud_logging.json` with CloudTrail/Config/GuardDuty coverage.
7. `cloud_secrets.json` with Secrets Manager/KMS posture notes.
8. `evidence.json` with raw CLI outputs, account context, and timestamps.
9. `findings.json` with risky configuration evidence.

## Evidence Consolidation
Use `summarize_aws_inventory.py` to consolidate JSON outputs into `cloud_inventory.json`.
Summarize IAM, storage, network, and logging evidence into their respective JSON outputs.

## Success Criteria
- Account scope and org context confirmed.
- IAM, storage, network, and logging posture documented.
- High-risk configurations documented with evidence.

## Tool References
- ../toolcards/awscli.md
- ../toolcards/prowler.md
- ../toolcards/scoutsuite.md
- ../toolcards/trivy.md
