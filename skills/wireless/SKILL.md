# Wireless Service Skill

## Overview
Service-first methodology for authorized wireless assessment with a focus on passive discovery, safe validation, and evidence-driven reporting.

## Scope Rules
1. Only operate on explicitly authorized wireless networks and bands.
2. Passive discovery is default; active attacks require explicit authorization.
3. Avoid deauthentication, WPS attacks, or credential capture unless authorized.
4. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Passive Discovery
- Identify SSIDs, BSSIDs, channels, and encryption types.
- Capture beacon/probe metadata for inventory and baseline signal strength.

### 2. Authentication Surface
- Detect WPA/WPA2/WPA3 and WPS availability.
- Validate whether enterprise auth (802.1X/EAP) is in use.
- Record cipher suites and management frame protection settings.

### 3. Safe Validation (Authorized)
- Capture handshake or PMKID only when explicitly authorized.
- Validate weak configurations (WPS enabled, legacy ciphers).
- Record whether client isolation is enabled and consistent.

### 4. Explicit-Only Actions
- Deauth, WPS PIN attempts, or credential attacks require explicit authorization.

## Service-First Workflow (Default)
1. Discovery: passive scans with `aircrack-ng` suite.
2. Inventory: record SSID/BSSID/channel/encryption.
3. Authorized validation: capture handshake/PMKID with `wifite` or `hcxtools`.
4. Enterprise check: confirm 802.1X/EAP posture and certificate validation when authorized.
5. Explicit-only: WPS attacks or phishing only when authorized.

## Deep Dives
Load references when needed:
1. Site survey and baseline inventory: `references/site_survey.md`
2. WPA/WPA2/WPA3 validation: `references/wpa_psk.md`
3. WPA-Enterprise posture: `references/wpa_enterprise.md`
4. WPS exposure review: `references/wps.md`
5. Rogue AP and evil twin indicators: `references/rogue_ap.md`
6. Advanced authorized playbook: `references/advanced.md`

## Evidence Collection
1. `wireless_inventory.json` with SSID/BSSID/channel/encryption details.
2. `wireless_auth_surface.json` with auth/cipher/WPS posture.
3. `wireless_handshake.json` with authorized capture metadata (timestamps, channels, files).
4. `evidence.json` with raw capture metadata and scan outputs.
5. `findings.json` with weak configuration or exposure evidence.

## Evidence Consolidation
Use `airodump_csv_to_json.py` to convert airodump CSV output into `wireless_inventory.json`.
Summarize auth posture and capture metadata into `wireless_auth_surface.json` and `wireless_handshake.json`.

## Success Criteria
- Wireless inventory captured safely.
- Security posture documented with evidence.
- Actions constrained to authorized networks.

## Tool References
- ../toolcards/aircrack-ng.md
- ../toolcards/airgeddon.md
- ../toolcards/bettercap.md
- ../toolcards/macchanger.md
- ../toolcards/wifite.md
- ../toolcards/wifiphisher.md
- ../toolcards/reaver.md
- ../toolcards/bully.md
- ../toolcards/hcxtools.md
- ../toolcards/tcpdump.md
- ../toolcards/tshark.md
