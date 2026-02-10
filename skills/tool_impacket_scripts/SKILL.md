# Tool: Impacket Scripts

## Overview
Use Impacket scripts for targeted remote execution and credential extraction within scope.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Select the least invasive script (wmiexec/smbexec vs psexec).
2. Use Kerberos (`-k`) or hash-based auth (`-hashes`) when appropriate.
3. Record exact command + output for evidence.

## Deep Dives
Load references as needed:
1. ../toolcards/impacket-scripts.md
2. references/advanced.md

## Evidence Collection
1. command outputs (stdout/stderr)
1. evidence.json with script + target details

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
