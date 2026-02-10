# Baseline Enumeration

## Goals
1. Identify local misconfigurations that could enable escalation.
2. Capture evidence without exploitation.
3. Record OS version, patch level, and service context.

## Safe Checks
1. OS version, patch level, installed software.
2. SUID/SGID binaries, scheduled tasks, and service permissions.
3. User group memberships and sudo privileges.

## Evidence Checklist
1. System inventory summary.
2. High-risk misconfig findings.
3. Permission evidence and file paths.
