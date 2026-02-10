# Tool: BloodHound

## Overview
Use BloodHound CE to analyze AD relationships and map attack paths to high-value targets.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Confirm scope (domain, OUs, time window) and approved collection sources.
2. Import scoped SharpHound collection output and validate completeness.
3. Run path queries (shortest paths to high-value groups, ACL-based escalation paths).
4. Capture proof (graph exports, query results, and path summaries).

## Deep Dives
Load references as needed:
1. ../toolcards/bloodhound.md
2. references/advanced.md

## Evidence Collection
1. bloodhound graph exports or screenshots of path queries
1. evidence.json with identified paths + affected principals

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
