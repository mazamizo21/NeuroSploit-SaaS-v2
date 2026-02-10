# Linux Persistence Indicators

## Goals
1. Identify common persistence locations without changes.
2. Record ownership and permissions.

## Safe Checks
- Cron jobs and systemd timers
- Systemd services and init scripts
- User shell profiles and startup scripts

## Evidence Checklist
1. Path and entry names.
2. Ownership and permissions.
3. Service names and enablement state.
