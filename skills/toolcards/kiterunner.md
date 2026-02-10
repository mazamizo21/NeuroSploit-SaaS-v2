# kiterunner Toolcard

## Overview
- Summary: Kiterunner is an API route discovery tool that uses wordlists to identify endpoints.

## Advanced Techniques
- Use API wordlists aligned to framework or provider patterns.
- Keep concurrency low for production endpoints.

## Safe Defaults
- Rate limits: low concurrency and conservative timeouts.
- Scope rules: explicit target only; avoid bypass or fuzzing unless authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/assetnote/kiterunner
