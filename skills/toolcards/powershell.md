# powershell Toolcard

## Overview
- Summary: PowerShell is a task-based command-line shell and scripting language for automation and configuration management.

## Advanced Techniques
- Use `-NoProfile` for consistent automation runs.
- Prefer explicit module imports and read-only cmdlets during reconnaissance.

## Safe Defaults
- Require explicit authorization before running scripts on external targets (external_exploit=explicit_only).
- Avoid execution policy bypasses or untrusted script sources.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://learn.microsoft.com/en-us/training/modules/introduction-to-powershell/
