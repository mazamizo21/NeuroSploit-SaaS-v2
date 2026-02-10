# Tool: theHarvester

## Overview
Use theHarvester to gather emails, hosts, subdomains, and URLs from public data sources.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Review which passive modules are available and require API keys.
2. Configure API keys in `api-keys.yaml` when required for sources.
3. Timebox collection and document sources used for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/theharvester.md
2. references/advanced.md

## Evidence Collection
1. theHarvester output files
1. evidence.json with sources used and counts

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
