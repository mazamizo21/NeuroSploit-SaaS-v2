# FTP Anonymous Access

## Goals
1. Determine whether anonymous login is enabled.
2. Identify read or write access without modifying files.
3. Record directory exposure and access scope.

## Safe Checks
1. `nmap --script ftp-anon`
2. `ftp` or `lftp` login with `anonymous` if authorized

## Indicators to Record
1. Anonymous read access to sensitive directories.
2. Anonymous write access (critical).
3. Access to backups or configuration files.

## Evidence Checklist
1. Anonymous login result.
2. Directory listing (read-only).
3. Notes on sensitive paths and access levels.
