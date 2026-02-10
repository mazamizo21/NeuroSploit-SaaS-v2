# xfreerdp Toolcard

## Overview
- Summary: xfreerdp is the FreeRDP client for connecting to RDP services and supports auth-only validation.

## Advanced Techniques
- Use `/auth-only` to validate credentials without starting a full session.
- Capture NTLM info using RDP scripts before attempting authentication.

## Safe Defaults
- Rate limits: avoid repeated auth attempts on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: rdp_info.json

## References
- https://manpages.debian.org/xfreerdp
