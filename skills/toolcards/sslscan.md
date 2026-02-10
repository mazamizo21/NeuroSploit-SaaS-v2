# sslscan Toolcard

## Overview
- Summary: sslscan enumerates TLS versions and cipher suites supported by a server.

## Advanced Techniques
- Use STARTTLS modes for services that upgrade from plaintext.
- Export results for evidence tracking.

## Safe Defaults
- Rate limits: conservative concurrency for external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: tls_report.json

## References
- https://github.com/DinoTools/sslscan
