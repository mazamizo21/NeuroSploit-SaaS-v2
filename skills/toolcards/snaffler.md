# snaffler Toolcard

## Overview
- Summary: Snaffler helps identify sensitive files and credential material in Windows environments.

## Advanced Techniques
- Focus collection on approved paths and exclude noisy directories.
- Preserve file metadata needed for reporting and remediation.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Minimize data collection and avoid bulk exfiltration.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/SnaffCon/Snaffler
