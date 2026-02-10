# Sensitive Data Exposure Deep Dive

## Checks
1. Identify secrets or sensitive data in responses, logs, or client-side bundles.
2. Validate cache-control headers for sensitive endpoints.
3. Confirm transport security and TLS configuration consistency.
4. Identify PII exposure and overbroad data fields in API responses.
5. Verify error handling does not leak stack traces or internal identifiers.

## Evidence Capture
1. Data exposure evidence with redaction where required.
2. Response field lists highlighting overexposed data.
3. Header snapshots for cache and transport controls.
