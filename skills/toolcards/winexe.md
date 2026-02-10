# winexe Toolcard

## Overview
- Summary: winexe remotely executes commands on Windows hosts over SMB.

## Advanced Techniques
- Prefer single-command execution and capture only required output.
- Use least-privileged credentials and keep target lists tightly scoped.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Avoid repeated authentication attempts to reduce lockout risk.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.samba.org/samba/docs/current/man-html/winexe.1.html
