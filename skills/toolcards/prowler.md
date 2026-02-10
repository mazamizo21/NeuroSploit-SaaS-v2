# prowler Toolcard

## Overview
- Summary: Prowler is an open-source cloud security tool for AWS that performs security assessments.

## Advanced Techniques
- Run with least-privilege read-only roles and scope to specific accounts.
- Export findings in structured formats for reporting.

## Safe Defaults
- Authorized accounts only; do not use on unknown tenants.
- Avoid write actions unless explicitly authorized.

## Evidence Outputs
- outputs: findings.json, evidence.json (as applicable)

## References
- https://github.com/prowler-cloud/prowler
