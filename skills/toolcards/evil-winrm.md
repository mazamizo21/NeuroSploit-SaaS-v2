# evil-winrm Toolcard

## Overview
- Summary: Evil-WinRM provides a WinRM shell for Windows servers and is commonly used for post-exploitation and administration via PowerShell Remoting Protocol (PSRP).

## Advanced Techniques
- Prefer authentication methods and transport options that are explicitly approved in scope.
- Use read-only queries or inventory commands for validation before deeper actions.

## Safe Defaults
- Avoid password spraying or repeated auth attempts on external targets.
- Use TLS when required and respect account lockout policies.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.kali.org/tools/evil-winrm-py/
- https://github.com/Hackplayers/evil-winrm
