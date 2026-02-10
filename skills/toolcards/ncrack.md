# ncrack Toolcard

## Overview
- Summary: Ncrack is a high-speed network authentication cracking tool.

## Advanced Techniques
- Use timing controls to balance speed and lockout risk.
- Split target sets to keep authentication attempts scoped.

## Safe Defaults
- Require explicit authorization for online credential attacks (external_exploit=explicit_only).
- Rate limits: keep low and stop on lockout signals.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://nmap.org/ncrack/
