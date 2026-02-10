# FTP Permissions Review

## Goals
1. Identify directory permissions and exposed data.
2. Avoid any file modifications.
3. Record read vs write access scope.

## Safe Checks
1. `LIST` or `ls` on authorized directories.
2. Record read/write permission hints.

## Indicators to Record
1. World-writable directories.
2. Exposed backup files or configs.
3. Access to hidden or restricted directories.

## Evidence Checklist
1. Directory listings (redacted if needed).
2. Notes on sensitive paths.
3. Access level notes (read vs write).
