# patator Toolcard

## Overview
- Summary: Patator is a multi-purpose brute-forcer with a modular design.

## Advanced Techniques
- Use protocol-specific modules and targeted input sets to reduce noise.
- Throttle attempts to respect lockout policies.

## Safe Defaults
- Require explicit authorization for online credential attacks (external_exploit=explicit_only).
- Rate limits: keep low and stop on lockout signals.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/lanjelot/patator
