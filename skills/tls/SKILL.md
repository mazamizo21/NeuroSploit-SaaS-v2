# TLS Service Skill

## Overview
Service-specific methodology for TLS/SSL configuration analysis and certificate validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and ports.
2. External targets: use conservative rate limits and avoid aggressive renegotiation.
3. No exploitation without explicit authorization.

## Methodology

### 1. Certificate and Chain Capture
- Capture leaf and intermediate certificates.
- Validate CN and SAN coverage for the target hostname.

### 2. Protocol and Cipher Enumeration
- Enumerate supported TLS versions.
- Identify weak ciphers or legacy protocol support.

### 3. Configuration Checks
- Review key sizes, signature algorithms, and certificate validity.
- Flag expired or self-signed certs and hostname mismatches.

### 4. Safe Validation
- Correlate findings with service context.
- Avoid disruptive testing on external targets.

## Deep Dives
Load references when needed:
1. Certificate chain validation: `references/certificate_chain.md`
2. Protocol and cipher support: `references/protocol_ciphers.md`
3. HSTS and OCSP checks: `references/hsts_ocsp.md`
4. Misconfiguration patterns: `references/misconfigurations.md`

## Evidence Collection
1. `tls_report.json` with protocol and cipher support (parsed from `sslscan` output).
2. `cert_chain.pem` or parsed certificate details.
3. `evidence.json` with raw `sslscan` output and certificate metadata.
4. `findings.json` with weak configuration evidence.

## Evidence Consolidation
Use `parse_sslscan.py` to convert `sslscan` output into `tls_report.json`.

## Success Criteria
- Certificate chain and hostname coverage verified.
- Protocol and cipher support documented.
- Weak TLS configurations documented with evidence.

## Tool References
- ../toolcards/sslscan.md
- ../toolcards/sslyze.md
