# Example Skill Skeleton

## Overview
Template skill that demonstrates the recommended structure and evidence workflow.

## Scope Rules
1. Use this skill only in lab or training environments.
2. Do not run against real targets.
3. Keep all actions read-only and non-destructive.

## Methodology

### 1. Inventory Capture
- Collect minimal metadata and store in `example_inventory.json`.

### 2. Evidence Packaging
- Store raw outputs in `evidence.json`.
- Document any findings in `findings.json`.

## Deep Dives
Load references when needed:
1. Template guidance: `references/overview.md`

## Service-First Workflow (Default)
1. Collect minimal sample data.
2. Convert sample output into `example_inventory.json`.
3. Store raw evidence and summarize findings.

## Evidence Collection
1. `example_inventory.json` with parsed inventory data.
2. `evidence.json` with raw sample output.
3. `findings.json` with any notes.

## Evidence Consolidation
Use `parse_example.py` to convert raw sample output into `example_inventory.json`.

## Success Criteria
- Example inventory captured.
- Evidence stored in expected files.

## Tool References
- ../toolcards/example.md
