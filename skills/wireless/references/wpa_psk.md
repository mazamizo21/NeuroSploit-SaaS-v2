# WPA/WPA2/WPA3 PSK Validation

## Goals
- Confirm encryption type and cipher suites.
- Document management frame protection (MFP/PMF) status.

## Authorized Validation
- Handshake or PMKID capture only when explicitly authorized.
- Record capture metadata (time, channel, file name).

## Evidence
- Store capture metadata in `wireless_handshake.json`.
- Note weak configurations (e.g., WPS enabled, legacy ciphers) in `findings.json`.
