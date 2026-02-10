# psexec.py Toolcard

## Overview
- Summary: psexec.py is an Impacket example script used for remote execution over SMB in Windows environments.

## Advanced Techniques
- Use only when explicit authorization covers remote execution.
- Prefer validation commands that do not modify system state.

## Safe Defaults
- Avoid running on external targets without explicit authorization.
- Limit command execution to approved validation steps.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/fortra/impacket/issues/1270
