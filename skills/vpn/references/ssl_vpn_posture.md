# SSL VPN TLS Posture

## Goals
1. Assess TLS configuration on SSL VPN endpoints.
2. Identify weak protocols and ciphers.
3. Record certificate and HSTS posture.

## Safe Checks
1. Use `sslscan` or `nmap --script ssl-enum-ciphers`.
2. Avoid authentication unless authorized.

## Indicators to Record
1. TLS 1.0 or 1.1 enabled.
2. Weak ciphers or missing HSTS.
3. Expired or mismatched certificates.

## Evidence Checklist
1. TLS scan output captured.
2. Summary of supported protocols and ciphers.
3. Certificate metadata and HSTS header evidence.
