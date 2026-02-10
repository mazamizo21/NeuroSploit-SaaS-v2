# Windows Persistence Indicators

## Goals
1. Identify common persistence locations without modifying them.
2. Record autorun entry ownership and path.

## Safe Checks
- Startup folders
- Run/RunOnce registry keys
- Scheduled tasks
- Services with auto-start

## Evidence Checklist
1. Location and entry names.
2. Timestamps and owner (if available).
3. File paths and digital signature status if available.
