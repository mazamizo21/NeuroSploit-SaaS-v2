# NGINX Gateway Playbook

## Identification Hints
- NGINX Gateway deployments often sit in front of APIs and may expose standard NGINX headers.
- In Kubernetes environments, NGINX Gateway Fabric can be used for Gateway API routing.

## Safe Checks
1. Identify gateway endpoints and route prefixes.
2. Inventory OpenAPI/Swagger specs and developer docs.
3. Validate TLS configuration and auth scheme consistency.

## Evidence Capture
- Record gateway type and route inventory.
- Capture TLS posture and auth requirements.

## References
- https://docs.nginx.com/nginx-gateway-fabric/
