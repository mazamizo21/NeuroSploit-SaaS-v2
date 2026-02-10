# Linux systemd Persistence

## Goals
- Identify system/user units that auto-start on boot or login.
- Record unit names, ExecStart paths, and owners.

## Evidence
- Summarize systemd units in `persistence_inventory.json`.
- Document risky units in `persistence_risks.json`.
