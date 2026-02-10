# Tool: TestDisk

## Overview
Use TestDisk (and PhotoRec when needed) to recover data within scope.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Confirm the target disk/image is authorized for recovery.
2. Run TestDisk analysis to locate lost partitions and files.
3. Use PhotoRec for file carving when partition recovery is insufficient.
4. Document recovered artifacts with hashes and locations.

## Deep Dives
Load references as needed:
1. ../toolcards/testdisk.md
2. references/advanced.md

## Evidence Collection
1. recovery logs
1. evidence.json with recovered files and hashes

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
