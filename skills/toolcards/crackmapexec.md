# crackmapexec Toolcard

## Overview
- Summary: CrackMapExec is a post-exploitation and enumeration toolkit for Windows/Active Directory environments that supports multiple protocols such as SMB, LDAP, MSSQL, WinRM, SSH, FTP, and RDP.

## Advanced Techniques
- Use protocol-specific enumeration modules to validate configuration and access without running intrusive actions.
- Prefer read-only modules unless explicit authorization is confirmed.

## Safe Defaults
- Avoid credential attacks or spraying on external targets unless explicitly authorized.
- Consider NetExec as the maintained continuation when available.

## Evidence Outputs
- outputs: findings.json, evidence.json (as applicable)

## References
- https://www.kali.org/tools/crackmapexec/
- https://www.kali.org/tools/netexec/
