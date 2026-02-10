# Tool: Fern WiFi Cracker

## Overview
Use Fern WiFi Cracker for guided GUI workflows in lab or authorized tests.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Verify dependencies (aircrack-ng, reaver, macchanger) before launch.
2. Select the minimum required attack type (WEP/WPA/WPS).
3. Record output and captured keys in the evidence log.

## Deep Dives
Load references as needed:
1. ../toolcards/fern-wifi-cracker.md
2. references/advanced.md

## Evidence Collection
1. fern output logs
1. evidence.json with attack type and results

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
