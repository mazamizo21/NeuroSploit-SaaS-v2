# winpeas Toolcard

## Overview
- Summary: WinPEAS is a Windows local privilege escalation enumeration script.

## Advanced Techniques
- Focus on read-only checks and prioritize high-signal findings.
- Collect only the evidence needed to support remediation.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Treat output as sensitive and minimize data collection.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/carlospolop/PEASS-ng
