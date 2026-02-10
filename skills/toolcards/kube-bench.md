# kube-bench Toolcard

## Overview
- Summary: kube-bench runs the CIS Kubernetes benchmark to identify misconfigurations.

## Advanced Techniques
- Select the benchmark version that matches the cluster version.
- Capture JSON output for evidence.

## Safe Defaults
- Read-only checks only.
- Run on authorized nodes or in trusted environments.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/aquasecurity/kube-bench
