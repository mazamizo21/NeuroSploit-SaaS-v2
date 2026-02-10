# Tool: subfinder

## Overview
Use Subfinder for fast passive subdomain discovery with source controls.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Start with default passive sources and review results.
2. Use `-ls` to audit available sources and choose scoped subsets.
3. Use `-recursive` or `-all` only when justified and timeboxed.
4. Record sources and output files for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/subfinder.md
2. references/advanced.md

## Evidence Collection
1. subfinder output files (txt/json)
1. evidence.json with sources used and output counts

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
