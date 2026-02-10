# Linux Credential Sources (Evidence-Only)

## Goals
1. Identify credential locations safely.
2. Minimize data collection and avoid modification.
3. Record file ownership and access scope.

## Typical Sources
- `/etc/passwd`, `/etc/shadow` (authorized, offline review)
- Shell history files
- SSH keys and authorized_keys
- Application config files and environment variables

## Safe Handling
1. Capture metadata and sample evidence only.
2. Redact secrets from reports.
3. Avoid copying full files unless explicitly authorized.
