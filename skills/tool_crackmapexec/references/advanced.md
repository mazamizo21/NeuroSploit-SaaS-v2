# Advanced Techniques

## Module Workflow
- Use `cme <proto> -L` to list modules, then `-M <module>` with `--options` to set module parameters explicitly.
- Keep read-only recon modules first (shares, users, groups, sessions) before any execution modules.

## SMB Recon Hooks
- `cme smb` supports focused enumeration flags like `--shares`, `--sessions`, `--users`, `--groups`, and `--rid-brute` for targeted validation.

## Evidence
- Preserve module output and annotate which flag produced each result (host, protocol, module/flag).
