# CI/CD Platform Fingerprints

## Goals
1. Identify platform type and version from banners and endpoints.
2. Capture exposed admin or metrics endpoints.
3. Record authentication requirements on key endpoints.

## Safe Checks
1. `httpx -title -server -status-code -tech-detect`
2. `nuclei -tags jenkins,gitlab,github,azure-devops`

## Indicators to Record
1. Publicly exposed admin consoles.
2. Unauthenticated metrics endpoints.
3. Legacy versions with known CVEs (record only).
4. Publicly accessible build logs or artifacts.

## Evidence Checklist
1. Endpoint list with detected tech.
2. Version or build metadata where visible.
3. Authentication status evidence for key endpoints.
