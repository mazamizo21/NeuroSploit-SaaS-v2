# Linux Filesystem Permissions Checklist

## Checks
1. World-writable files in sensitive directories (`/etc`, `/var`, `/opt`).
2. SUID/SGID binaries outside approved baselines.
3. Writable service directories for systemd units.
4. Permissions on `/etc/shadow`, `/etc/passwd`, and `/etc/sudoers`.
5. `noexec`, `nodev`, `nosuid` on `/tmp`, `/var/tmp`, `/dev/shm` where required.
6. World-writable cron or init directories.

## Evidence Capture
1. File paths, permissions, and ownership evidence.
2. Mount option evidence for temporary filesystems.
