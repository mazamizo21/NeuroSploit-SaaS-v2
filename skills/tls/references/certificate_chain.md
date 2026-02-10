# Certificate Chain Validation

## Goals
1. Capture leaf and intermediate certificates.
2. Validate CN and SAN coverage for the target hostname.
3. Record key size and signature algorithm.

## Safe Checks
1. `openssl s_client -connect host:443 -servername host -showcerts`
2. Record subject, issuer, and validity dates.

## Indicators to Record
1. CN/SAN mismatch.
2. Expired or not-yet-valid certificates.
3. Self-signed or untrusted issuers.
4. Weak key sizes or SHA1 signatures.

## Evidence Checklist
1. PEM chain (if allowed).
2. Parsed certificate metadata.
3. Key size and signature algorithm notes.
