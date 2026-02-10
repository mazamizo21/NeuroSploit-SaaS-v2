# netexec Toolcard

## Overview
- Summary: NetExec is a network service exploitation tool designed to automate assessing the security of large Windows/Active Directory networks and is the continuation of CrackMapExec.

## Advanced Techniques
- Use protocol modules aligned to discovered services to avoid unnecessary noise.
- Keep a strict separation between enumeration and exploitation phases.

## Safe Defaults
- Prefer read-only enumeration modules on external targets.
- Use conservative concurrency and avoid repeated auth attempts.

## Evidence Outputs
- outputs: findings.json, evidence.json (as applicable)

## References
- https://www.kali.org/tools/netexec/
- https://github.com/Pennyw0rth/NetExec
