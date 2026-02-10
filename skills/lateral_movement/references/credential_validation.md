# Credential Validation

## Goals
1. Validate discovered credentials on authorized hosts only.
2. Avoid password spraying unless explicitly authorized.
3. Record authentication method and scope.

## Safe Checks
1. Use a single authentication attempt per host.
2. Record success or failure once.

## Evidence Checklist
1. Target host and method used.
2. Success/failure outcome.
3. Credential source and authorization reference.
