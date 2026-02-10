# Wireless Advanced Playbook (Authorized Only)

## Intent
Deepen wireless assessment without disrupting production networks.

## Safe Checks
1. Validate encryption standards (WPA2/WPA3) and WPS exposure.
2. Capture handshake or PMKID only when explicitly authorized.
3. Identify rogue AP exposure and weak client isolation.
4. Document channel overlap and signal dominance for high-risk SSIDs.

## Authorized Deep Dives
1. Passive rogue AP discovery by SSID duplication and unexpected vendor OUIs.
2. Confirm enterprise auth usage (802.1X) and note missing RADIUS protections.
3. Validate client isolation by reviewing configuration evidence or approved tests.

## Evidence Capture
1. SSID/BSSID/channel/encryption and WPS status.
2. Handshake or PMKID capture metadata (timestamps, channels, capture files).
3. Rogue AP indicators: SSID duplicates, signal anomalies, vendor mismatches.
4. Client isolation posture and supporting evidence.

## Explicit-Only Actions
- Deauthentication, WPS PIN attacks, or phishing require explicit authorization.
