# Workload Exposure

## Goals
1. Identify public services and exposed workloads.
2. Capture namespace and service posture.
3. Record ingress TLS settings and hostnames.

## Safe Checks
1. `kubectl get svc -A -o json`
2. `kubectl get ingress -A -o json`

## Indicators to Record
1. LoadBalancer services on public networks.
2. Ingresses with weak TLS settings.
3. Services exposing admin or metrics endpoints.

## Evidence Checklist
1. Public service list.
2. Ingress host summary.
3. TLS secret usage and hostname evidence.
