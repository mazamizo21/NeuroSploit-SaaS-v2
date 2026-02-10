# Linux Escalation Vectors (Evidence-Only)

## Goals
1. Identify common escalation paths without exploitation.
2. Document misconfigurations and weak permissions.
3. Record service context and ownership.

## Safe Checks
1. SUID/SGID binaries with unsafe paths.
2. Writable service configs or cron jobs.
3. World-writable directories in PATH.
4. Writable systemd units or service scripts.

## Evidence Checklist
1. Misconfiguration list with file paths.
2. Permission evidence.
3. Ownership and service association notes.
