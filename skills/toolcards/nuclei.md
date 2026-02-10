# nuclei Toolcard

## Overview
- Summary: Nuclei is a template-based scanner that runs YAML templates against targets to identify vulnerabilities and misconfigurations.

## Advanced Techniques
- Filter templates by severity or tags to keep scans scoped.
- Use JSON output to feed into evidence pipelines.
- Keep templates updated and pin to approved template sets.

## Safe Defaults
- Rate limits: conservative concurrency on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: findings.json, evidence.json

## References
- https://docs.projectdiscovery.io/opensource/nuclei
