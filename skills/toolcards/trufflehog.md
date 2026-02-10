# trufflehog Toolcard

## Overview
- Summary: TruffleHog scans repositories and sources for secrets and sensitive data.

## Advanced Techniques
- Use regex allowlists for known safe patterns.
- Prefer report outputs for evidence capture.

## Safe Defaults
- Explicit authorization required for secrets scanning.
- Redact secret values in outputs unless explicitly required.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/trufflesecurity/trufflehog
