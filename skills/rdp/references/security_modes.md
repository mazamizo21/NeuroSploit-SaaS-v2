# RDP Security Modes and Encryption

## Goals
1. Identify security layer (RDP, TLS, CredSSP/NLA).
2. Capture encryption level and certificate details.
3. Record whether NLA is required or optional.

## Safe Checks
1. Use `nmap` scripts: `rdp-enum-encryption` and `rdp-ntlm-info`.
2. Avoid repeated connections or brute force attempts.

## What to Record
1. NLA (CredSSP) supported or required.
2. TLS/SSL supported.
3. RDP encryption level.
4. Any certificate subject/issuer details (no private data).
5. RDP security layer order (if exposed).
