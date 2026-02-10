# kerbrute Toolcard

## Overview
- Summary: kerbrute is a Kerberos-based tool for quickly enumerating valid Active Directory accounts without sending traffic to the DC's lockout controls.

## Advanced Techniques
- Use user enumeration mode before any password testing.
- Keep wordlists tightly scoped to reduce lockout risk.

## Safe Defaults
- Avoid password spraying on external targets unless explicitly authorized.
- Respect lockout policies and stop on signs of account lockout.

## Evidence Outputs
- outputs: findings.json, evidence.json (as applicable)

## References
- https://github.com/ropnop/kerbrute
