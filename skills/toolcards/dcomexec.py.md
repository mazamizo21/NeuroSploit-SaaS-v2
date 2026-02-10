# dcomexec.py Toolcard

## Overview
- Summary: dcomexec.py is an Impacket example for executing commands on a target via DCOM.

## Advanced Techniques
- Prefer single-command execution over long-lived shells.
- Use least-privileged credentials and narrow host targeting.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Avoid repeated authentication attempts to reduce lockout risk.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://sources.debian.org/src/impacket/0.10.0-4/examples/dcomexec.py/
