# beroot Toolcard

## Overview
- Summary: BeRoot is a set of scripts for privilege escalation checks.

## Advanced Techniques
- Run read-only checks first and focus on validated misconfigurations.
- Capture only the evidence required for reporting.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Treat output as sensitive and minimize data collection.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/AlessandroZ/BeRoot
