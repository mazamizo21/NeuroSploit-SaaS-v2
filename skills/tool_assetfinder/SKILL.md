# Tool: assetfinder

## Overview
Use assetfinder for quick passive discovery of related domains/subdomains.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Run with `--subs-only` when you only need subdomains.
2. De-duplicate and validate results before downstream scans.
3. Record output and sources for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/assetfinder.md
2. references/advanced.md

## Evidence Collection
1. assetfinder output list
1. evidence.json with target + result counts

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
