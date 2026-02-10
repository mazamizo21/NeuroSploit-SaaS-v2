# Tool: Amass

## Overview
Use Amass for scoped OSINT, DNS enumeration, and graph analysis of target infrastructure.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Run `intel` for high-level OSINT on the organization/domain.
2. Use `enum` for DNS enumeration with minimal active methods unless authorized.
3. Use `viz` for graph output and `db` for reviewing historical enumerations.
4. Record sources and output files for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/amass.md
2. references/advanced.md

## Evidence Collection
1. amass output files (JSON/graph outputs)
1. evidence.json with domains, sources, and enumeration mode

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
