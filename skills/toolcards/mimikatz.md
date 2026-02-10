# mimikatz Toolcard

## Overview
- Summary: Mimikatz is a Windows security research tool used to extract credentials such as plaintext passwords, hashes, and Kerberos tickets from memory.

## Advanced Techniques
- Limit collection scope to approved systems and sessions.
- Capture only the minimum evidence necessary for validation.

## Safe Defaults
- Do not run on external targets without explicit authorization.
- Coordinate with defenders to avoid disrupting endpoint protections.

## Evidence Outputs
- outputs: creds.json, evidence.json (as applicable)

## References
- https://www.kali.org/tools/mimikatz/
