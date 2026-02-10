# awscli Toolcard

## Overview
- Summary: The AWS Command Line Interface (AWS CLI) is a unified tool to manage AWS services from the command line.

## Advanced Techniques
- Prefer read-only calls for inventory and configuration review.
- Use scoped profiles and least-privilege roles.

## Safe Defaults
- Authorized accounts only; do not use on unknown tenants.
- Avoid write or delete actions unless explicitly authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html
