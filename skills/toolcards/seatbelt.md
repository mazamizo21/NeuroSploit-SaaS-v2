# seatbelt Toolcard

## Overview
- Summary: Seatbelt is a C# project for collecting system and security-related data from Windows hosts to support situational awareness and defense review.

## Advanced Techniques
- Use collection categories that match the engagement scope and avoid sensitive data over-collection.
- Run in read-only mode and collect only approved data points.

## Safe Defaults
- Do not run on external targets without explicit authorization.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/GhostPack/Seatbelt
