# atexec.py Toolcard

## Overview
- Summary: atexec.py executes a command on the target machine through the Task Scheduler service and returns the output.

## Advanced Techniques
- Use for one-shot validation commands rather than long-running tasks.
- Prefer short commands and collect only minimal output for evidence.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Avoid repeated task creation and clean up artifacts where allowed.

## Evidence Outputs
- outputs: evidence.json (as applicable)

## References
- https://sources.debian.org/src/impacket/0.10.0-4/examples/atexec.py/
