# smbexec.py Toolcard

## Overview
- Summary: smbexec.py provides a semi-interactive shell by executing commands with the SMBExec approach.

## Advanced Techniques
- Prefer non-interactive commands and short sessions.
- Collect minimal output and avoid lateral movement without explicit scope.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Rate-limit attempts to avoid account lockouts.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://sources.debian.org/src/impacket/0.10.0-4/examples/smbexec.py/
