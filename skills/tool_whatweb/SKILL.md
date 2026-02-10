# Tool: WhatWeb

## Overview
Use WhatWeb to fingerprint web technologies with controlled aggression levels.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start with low aggression and increase only when authorized.
2. Record identified technologies and versions.
3. Export logs for evidence and correlation with other scans.

## Deep Dives
Load references as needed:
1. ../toolcards/whatweb.md
2. references/advanced.md

## Evidence Collection
1. whatweb output logs
1. evidence.json with aggression level and detected tech

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
