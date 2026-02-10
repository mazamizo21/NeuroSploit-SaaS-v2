# Tool: WiFiPumpkin3

## Overview
Use WiFiPumpkin3 for controlled rogue AP and traffic interception tests.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Validate AP-mode adapter support and required dependencies.
2. Enable only the modules required for the test (RogueAP, proxy, capture).
3. Collect logs for DNS/HTTP activity and credentials (redacted).

## Deep Dives
Load references as needed:
1. ../toolcards/wifipumpkin3.md
2. references/advanced.md

## Evidence Collection
1. WiFiPumpkin3 logs and module outputs
1. evidence.json with modules enabled and target context

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
