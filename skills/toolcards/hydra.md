# hydra Toolcard

## Overview
- Summary: THC Hydra is a parallelized network logon cracker that supports many protocols.

## Advanced Techniques
- Use service-specific modules and narrow credential sets to reduce noise.
- Throttle task counts to respect lockout policies.

## Safe Defaults
- Require explicit authorization for online credential attacks (external_exploit=explicit_only).
- Rate limits: keep low and stop on lockout signals.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://raw.githubusercontent.com/vanhauser-thc/thc-hydra/master/README
