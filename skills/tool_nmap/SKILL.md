# Tool: Nmap

## Overview
Use Nmap for service discovery and targeted NSE script execution.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Run a baseline scan (ports + service detection).
2. Select safe or targeted NSE script categories.
3. Use `--script-args` only for approved credentials and inputs.

## Deep Dives
Load references as needed:
1. ../toolcards/nmap.md
2. references/advanced.md

## Evidence Collection
1. nmap output files (normal/grepable/xml)
1. evidence.json with script categories and arguments

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
