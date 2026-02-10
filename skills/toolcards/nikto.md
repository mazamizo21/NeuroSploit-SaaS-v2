# nikto Toolcard

## Overview
- Summary: Nikto is a web server scanner that checks for dangerous files, outdated software, and common misconfigurations.

## Advanced Techniques
- Use tuning options to scope checks to relevant test categories.
- Prefer output formats that can be parsed into structured evidence.

## Safe Defaults
- Rate limits: avoid aggressive scans on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: findings.json, evidence.json

## References
- https://www.kali.org/tools/nikto/
