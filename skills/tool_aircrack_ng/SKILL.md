# Tool: Aircrack-ng

## Overview
Use Aircrack-ng components for scoped wireless capture and validation.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Enable monitor mode and confirm the capture interface.
2. Use airodump-ng for channel-focused capture and handshake collection.
3. Validate handshakes and perform offline cracking only with approved wordlists.

## Deep Dives
Load references as needed:
1. ../toolcards/aircrack-ng.md
2. references/advanced.md

## Evidence Collection
1. pcap capture files
1. evidence.json with channel, BSSID, and capture window

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
