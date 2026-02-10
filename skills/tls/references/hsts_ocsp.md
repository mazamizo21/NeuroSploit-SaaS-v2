# HSTS and OCSP

## Goals
1. Identify HSTS enforcement where applicable.
2. Capture OCSP stapling or revocation status signals.
3. Record max-age and includeSubDomains flags.

## Safe Checks
1. Review `Strict-Transport-Security` header on HTTPS endpoints.
2. Use `openssl s_client -status` for OCSP stapling where supported.

## Indicators to Record
1. HSTS missing on public HTTPS endpoints.
2. OCSP stapling disabled (note only).
3. Short or zero max-age values.

## Evidence Checklist
1. HSTS header values.
2. OCSP status output (if available).
3. Header evidence for includeSubDomains or preload flags.
