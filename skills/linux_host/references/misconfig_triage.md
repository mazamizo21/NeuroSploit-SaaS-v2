# Linux Misconfiguration Triage Playbook (Authorized Only)

## Intent
Identify high-risk misconfigurations without exploitation.

## Safe Checks
1. Identify writable system paths and world-writable files in sensitive directories.
2. Enumerate SUID/SGID binaries and compare against allowlists.
3. Review sudoers for NOPASSWD or overly broad rules.
4. Inspect cron jobs and systemd services for unsafe permissions.

## Evidence Capture
- File paths and permissions for risky entries.
- Sudoers excerpts and service definitions.

## Explicit-Only Actions
- Do not execute binaries or exploit misconfigurations without explicit authorization.
