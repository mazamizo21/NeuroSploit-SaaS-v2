# adidnsdump Toolcard

## Overview
- Summary: adidnsdump dumps Active Directory Integrated DNS data as any authenticated user.

## Advanced Techniques
- Target only approved zones and limit data volume.
- Prefer read-only collection and store outputs securely.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Minimize data collection and restrict output access.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/dirkjanm/adidnsdump
