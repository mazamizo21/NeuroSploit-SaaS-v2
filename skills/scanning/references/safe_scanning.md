# Safe Scanning Practices

## Goals
1. Reduce impact and false positives.
2. Keep scans scoped to discovered services.
3. Preserve clear evidence of scan configuration.

## Safe Checks
1. Use conservative rate limits and retries on external targets.
2. Scope scans to known services and ports only.
3. Limit severity levels when appropriate and avoid destructive templates.
4. Stagger scans to avoid overlapping load on the same host.

## Evidence Checklist
1. Scan configuration (templates, severity, rate, retries).
2. Scope list (targets and ports).
3. Throttling or errors observed (timeouts, 429, 503).
