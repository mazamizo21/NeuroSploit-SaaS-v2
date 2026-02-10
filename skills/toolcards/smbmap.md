# smbmap Toolcard

## Overview
- Summary: SMBMap is an SMB enumeration tool that identifies share permissions, lists directories, and can perform limited file operations.

## Advanced Techniques
- Use read-only listing modes to validate access without modifying files.
- Filter output to focus on sensitive shares and avoid excessive recursion.

## Safe Defaults
- Avoid write or command execution features without explicit authorization.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: smb_shares.json, evidence.json (as applicable)

## References
- https://github.com/ShawnDEvans/smbmap
