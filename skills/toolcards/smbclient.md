# smbclient Toolcard

## Overview
- Summary: smbclient is an FTP-like SMB/CIFS client for listing shares and accessing files.

## Advanced Techniques
- Use anonymous mode to safely test guest access.
- Use credentials only when explicitly provided and authorized.

## Safe Defaults
- Rate limits: avoid repeated auth attempts on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: smb_shares.json

## References
- https://www.samba.org/samba/samba/docs/man/manpages/smbclient.1.html
