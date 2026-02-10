# wapiti Toolcard

## Overview
- Summary: Wapiti is a web vulnerability scanner written in Python that acts as a black-box scanner to identify common web flaws.

## Advanced Techniques
- Prioritize read-only checks and validate findings with minimal impact.
- Keep scans scoped to approved paths and parameters.

## Safe Defaults
- Rate limits: conservative concurrency on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: findings.json, evidence.json (as applicable)

## References
- https://github.com/wapiti-scanner/wapiti
