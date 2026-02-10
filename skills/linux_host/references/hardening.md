# Linux Hardening Playbook (Read-Only)

## Intent
Validate hardening controls and configuration baselines.

## Safe Checks
1. Verify firewall status and policy (ufw/nftables/iptables).
2. Validate SELinux/AppArmor mode and enforcement.
3. Confirm audit logging and log rotation configurations.
4. Review SSH hardening (protocol versions, root login, MFA).

## Evidence Capture
- Control status and configuration excerpts.
- SSH and PAM policy evidence.
