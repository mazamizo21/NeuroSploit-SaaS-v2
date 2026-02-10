# Tool: Evil-WinRM

## Overview
Use Evil-WinRM to obtain a scoped WinRM shell and validate access.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Validate WinRM access with provided credentials or hash.
2. Run minimal proof commands (whoami, hostname, ipconfig).
3. Use upload/download only for evidence collection, not persistence.
4. Record session commands for handoff if enabled.

## Deep Dives
Load references as needed:
1. ../toolcards/evil-winrm.md
2. references/advanced.md

## Evidence Collection
1. handoff.json with WinRM session command
1. evidence.json with access proof

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
