# WPA-Enterprise (802.1X/EAP) Posture

## Goals
- Identify EAP methods (PEAP, EAP-TLS, TTLS, etc.).
- Confirm certificate validation and server identity checks.

## Authorized Checks
- Document whether clients validate RADIUS server certificates.
- Record any missing protections or weak configurations.

## Evidence
- Capture EAP method details in `wireless_auth_surface.json`.
- Note posture findings in `findings.json`.
