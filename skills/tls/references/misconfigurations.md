# TLS Misconfiguration Patterns

## Goals
1. Identify common TLS issues with minimal impact.
2. Provide consistent evidence and risk notes.
3. Record service context for misconfiguration impact.

## Indicators to Record
1. Weak key sizes (RSA < 2048, ECDSA < 256).
2. SHA1 signatures.
3. Self-signed or mismatched hostname.
4. Expired certificates.
5. Missing intermediate certificates.

## Evidence Checklist
1. Key size and signature algorithm.
2. Validity window and issuer.
3. Matching hostname evidence.
4. Full chain and missing intermediates evidence.
