# IMAP TLS Posture

## Goals
1. Determine whether STARTTLS is supported and enforced.
2. Capture TLS version and certificate metadata.
3. Record protocol and cipher posture.

## Safe Checks
1. Use `openssl s_client -starttls imap` when authorized and rate-limited.
2. Prefer IMAPS (993) when available.

## Indicators to Record
1. STARTTLS missing on external endpoints.
2. Weak TLS versions or ciphers.
3. Certificate expired or mismatched.

## Evidence Checklist
1. TLS negotiation output.
2. Certificate subject, SANs, and expiry dates.
3. Noted protocol and cipher details.
