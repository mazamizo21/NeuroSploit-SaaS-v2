# SMB Service Skill

## Overview
Service-specific methodology for SMB enumeration, share discovery, and safe access validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: no brute force or password spraying unless explicit authorization is confirmed.
3. Avoid disruptive actions such as share modifications or file writes.
4. Exploit or lateral-movement workflows require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. SMB Version and Security Mode
- Identify SMB dialects and signing requirements.
- Capture banner and OS hints where available.

### 2. Share Enumeration
- List available shares and permissions.
- Check for guest or anonymous access safely.

### 3. Safe Access Validation
- Use provided credentials only.
- Avoid destructive operations and file writes unless authorized.

## Service-First Workflow (Default)
1. Discovery: identify SMB dialects, signing, and OS hints via `nmap`.
2. Share enumeration: list shares and permissions with `smbclient`.
3. Access validation: read-only checks using provided credentials only.
4. Explicit-only workflows: any file writes, remote execution, or lateral movement only when authorization is confirmed.

## Deep Dives
Load references when needed:
1. Dialects and signing posture: `references/signing_and_dialects.md`
2. Null session and guest access: `references/null_sessions.md`
3. Share permissions review: `references/share_permissions.md`

## Evidence Collection
1. `smb_shares.json` with share names and access results (parsed from `smbclient` output).
2. `evidence.json` with raw `smbclient` output and Nmap script evidence.
3. `findings.json` with risky configurations and evidence.

## Evidence Consolidation
Use `parse_smbclient.py` to convert `smbclient -L` output into `smb_shares.json`.

## Success Criteria
- SMB dialects and signing settings documented.
- Shares enumerated with access levels.
- Risky access documented with evidence.

## Tool References
- ../toolcards/smbclient.md
- ../toolcards/nmap.md
