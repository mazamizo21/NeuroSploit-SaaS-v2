# Tool: Wifiphisher

## Overview
Use Wifiphisher for authorized rogue AP tests and controlled phishing simulations.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Confirm AP and monitor mode adapters meet requirements.
2. Select phishing scenarios/templates appropriate to scope.
3. Capture evidence of client association and credential collection.

## Deep Dives
Load references as needed:
1. ../toolcards/wifiphisher.md
2. references/advanced.md

## Evidence Collection
1. wifiphisher logs and captured credentials (redacted)
1. evidence.json with scenario and adapter details

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
