# Tool: YARA

## Overview
Use YARA rules to scan files or directories for known patterns.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select or author YARA rules matching the investigation objective.
2. Run scans against approved paths or evidence sets.
3. Review match output and capture relevant artifacts.

## Deep Dives
Load references as needed:
1. ../toolcards/yara.md
2. references/advanced.md

## Evidence Collection
1. rule files and match outputs
1. evidence.json with rule set + match summary

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
