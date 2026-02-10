# Tool: NetExec

## Overview
Use NetExec to validate creds, enumerate access, and perform scoped remote actions.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Validate creds with a single check per host/service.
2. Enumerate shares/sessions/admin access only when authorized.
3. Run limited commands to prove access (no persistence by default).
4. Capture output artifacts for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/netexec.md
2. references/advanced.md

## Evidence Collection
1. credential validation logs
1. evidence.json with successful host/service pairs

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
