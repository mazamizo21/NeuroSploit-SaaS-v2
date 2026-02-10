# Tool: Autopsy

## Overview
Use Autopsy to triage disk images and data sources with scoped ingest modules.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Create a case and add the approved data source (image, directory, device).
2. Select ingest modules and/or ingest profiles matching the objective.
3. Run ingest and review results in the Results/Blackboard views.
4. Export only approved artifacts and record evidence paths.

## Deep Dives
Load references as needed:
1. ../toolcards/autopsy.md
2. references/advanced.md

## Evidence Collection
1. Autopsy case summary and module outputs
1. evidence.json with modules used and key artifacts

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
