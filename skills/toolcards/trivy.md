# trivy Toolcard

## Overview
- Summary: Trivy is a comprehensive vulnerability scanner for containers and other artifacts.

## Advanced Techniques
- Use SBOM generation and offline databases when needed.
- Scope scans to approved images and repositories.

## Safe Defaults
- Authorized assets only; do not scan third-party images without permission.
- Avoid pushing results to external services unless approved.

## Evidence Outputs
- outputs: findings.json, evidence.json (as applicable)

## References
- https://github.com/aquasecurity/trivy
