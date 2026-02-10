# Tool: CeWL

## Overview
Use CeWL to generate scoped wordlists from target content.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Set crawl depth and minimum word length to control output.
2. Restrict to in-scope domains and pages.
3. Save wordlists with a clear provenance note.

## Deep Dives
Load references as needed:
1. ../toolcards/cewl.md
2. references/advanced.md

## Evidence Collection
1. generated wordlists
1. evidence.json with crawl depth and target URLs

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
