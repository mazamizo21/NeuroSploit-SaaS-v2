# Disk Triage

## Goals
- Identify file systems, user profiles, and configuration directories.
- Extract sensitive files with minimal alteration.

## Notes
- Prefer read-only mounts or copy-on-write when possible.
- Capture file hashes before and after processing.
