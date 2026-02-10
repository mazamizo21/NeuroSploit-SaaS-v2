# medusa Toolcard

## Overview
- Summary: Medusa is a speedy, parallel, and modular login brute-forcer.

## Advanced Techniques
- Use module-specific options for each protocol and keep target lists scoped.
- Tune concurrency to avoid account lockouts.

## Safe Defaults
- Require explicit authorization for online credential attacks (external_exploit=explicit_only).
- Rate limits: keep low and stop on lockout signals.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/jmk-foofus/medusa
