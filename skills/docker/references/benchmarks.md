# Docker Benchmarks and Hardening

## Goals
1. Use CIS benchmarks for baseline posture.
2. Prioritize critical findings for remediation.
3. Record benchmark version and profile used.

## Safe Checks
1. `docker-bench-security` (read-only)
2. Capture pass/fail summary only

## Indicators to Record
1. Insecure daemon configuration flags.
2. Missing user namespace remapping.
3. Containers running in privileged mode.

## Evidence Checklist
1. Benchmark summary.
2. High-risk findings list.
3. Benchmark version and runtime context.
