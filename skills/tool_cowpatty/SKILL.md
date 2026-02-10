# Tool: cowpatty

## Overview
Use cowpatty for offline WPA/WPA2-PSK dictionary verification.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Validate handshake capture before cracking.
2. Use `genpmk` to precompute hashes for a specific SSID when appropriate.
3. Record wordlist used and result status for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/cowpatty.md
2. references/advanced.md

## Evidence Collection
1. cowpatty output logs
1. evidence.json with SSID and wordlist

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
