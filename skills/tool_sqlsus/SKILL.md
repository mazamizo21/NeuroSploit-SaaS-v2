# Tool: sqlsus

## Overview
Use sqlsus for MySQL injection with explicit configuration files.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Define target, injection points, and taming options in config.
2. Validate injection before data extraction.
3. Capture outputs and proof for reporting.

## Deep Dives
Load references as needed:
1. ../toolcards/sqlsus.md
2. references/advanced.md

## Evidence Collection
1. sqlsus logs/output
1. evidence.json with config and modes

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
