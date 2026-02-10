# kubectl Toolcard

## Overview
- Summary: kubectl is the Kubernetes command-line tool for interacting with clusters.

## Advanced Techniques
- Use `kubectl auth can-i` to validate RBAC permissions.
- Use `--all-namespaces` for scoped inventory.

## Safe Defaults
- Read-only commands only unless explicitly authorized.
- Use provided kubeconfig contexts.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://v1-33.docs.kubernetes.io/docs/reference/kubectl/
