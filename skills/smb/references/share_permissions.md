# Share Permissions Review

## Goals
1. Identify share permissions and access levels.
2. Record read vs write exposure without modifying content.
3. Note sensitive share names and paths.

## Safe Checks
1. Use `smbclient` in read-only mode when possible.
2. Avoid file writes or deletions.

## Indicators to Record
1. Shares with guest or anonymous access.
2. Shares with write permissions for low-privilege users.
3. Administrative shares exposed unexpectedly.
4. Sensitive file patterns in share listings.

## Evidence Checklist
1. Share list with access results.
2. Notes on sensitive share names or paths.
3. Read vs write access evidence.
