# docker-bench-security Toolcard

## Overview
- Summary: Docker Bench Security runs checks against the CIS Docker Benchmark for host and daemon configuration.

## Advanced Techniques
- Run on authorized hosts to capture system-level configuration evidence.
- Export results to structured logs for reporting.

## Safe Defaults
- Explicit authorization required for host-level checks.
- Avoid running on shared production hosts without maintenance windows.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/docker/docker-bench-security
