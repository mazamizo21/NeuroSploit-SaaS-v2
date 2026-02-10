# Tool: Recon-ng

## Overview
Use recon-ng workspaces to organize OSINT modules and evidence for each engagement.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Create or load a workspace for each engagement.
2. Use the marketplace to install modules and review dependency/key requirements.
3. Set global options (verbosity, proxy) before module execution.
4. Record module outputs and reports as evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/recon-ng.md
2. references/advanced.md

## Evidence Collection
1. workspace database and reports
1. evidence.json with modules used and outputs

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
