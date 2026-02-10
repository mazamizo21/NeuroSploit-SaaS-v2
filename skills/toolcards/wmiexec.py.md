# wmiexec.py Toolcard

## Overview
- Summary: wmiexec is an Impacket script that executes a semi-interactive shell over WMI and is packaged in Kali as `impacket-wmiexec`.

## Advanced Techniques
- Use only when explicit authorization covers remote execution.
- Prefer validation commands that do not modify system state.

## Safe Defaults
- Avoid running on external targets without explicit authorization.
- Limit command execution to approved validation steps.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.kali.org/tools/impacket/
