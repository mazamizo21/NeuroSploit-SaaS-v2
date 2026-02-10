# Tool: Wifite

## Overview
Use Wifite to automate capture and validation steps while staying within scope.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Run with verbose logging to record underlying tool usage.
2. Target specific BSSID/ESSID/channel to reduce noise.
3. Resume sessions after interruptions when needed.

## Deep Dives
Load references as needed:
1. ../toolcards/wifite.md
2. references/advanced.md

## Evidence Collection
1. wifite output logs
1. evidence.json with target filters and attack modes

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
