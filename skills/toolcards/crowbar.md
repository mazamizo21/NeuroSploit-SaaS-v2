# crowbar Toolcard

## Overview
- Summary: Crowbar is a brute force tool for penetration tests that supports protocols not covered by Hydra.

## Advanced Techniques
- Use service-specific modules and narrow target sets.
- Throttle attempts to respect lockout policies.

## Safe Defaults
- Require explicit authorization for online credential attacks (external_exploit=explicit_only).
- Rate limits: keep low and stop on lockout signals.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/galkan/crowbar
